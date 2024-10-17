# celery_worker.py
# celery -A celery_worker worker --loglevel=info -P solo

import os
import logging
from minio import Minio
from minio.error import S3Error
#import mysql.connector
#from mysql.connector import Error
from datetime import datetime
#import torch
#from diffusers import StableDiffusionXLPipeline
#from diffusers.models.lora import LoRACompatibleConv
from celery import Celery
#import json
#from typing import Optional
import redis  # Redis 라이브러리 추가
#import time

# MySQL 데이터베이스 설정
db_config = {
    'host': '118.67.128.129',
    'port': 21212,
    'user': 'root',
    'password': 'root',  # 실제 비밀번호를 사용하세요
    'database': 'ohmyservice_database'  # 사용할 데이터베이스 이름
}

# MinIO 클라이언트 설정
minio_client = Minio(
    "118.67.128.129:9000",
    access_key="minio",
    secret_key="minio1234",
    secure=False
)
bucket_name = "test"

# 로깅 설정
logging.basicConfig(level=logging.INFO)

#logging.info(f"Is torch.cuda is available? : {torch.cuda.is_available()}")

#if torch.cuda.is_available():
    #logging.info(f"GPU is available. Using {torch.cuda.get_device_name(0)}")
#else:
    #logging.info("GPU is not available, using CPU instead.")

# Redis를 백엔드로 사용하도록 Celery 설정
app = Celery('app.celery_worker', broker='amqp://guest:guest@118.67.128.129:5672//', backend='redis://118.67.128.129:6379/0')
app.conf.update(
    broker_connection_retry_on_startup=True,
    broker_pool_limit=None,
    task_acks_late=True,
    broker_heartbeat=None,
    worker_prefetch_multiplier=1,
)

# Redis 클라이언트 초기화
redis_client = redis.Redis(host='118.67.128.129', port=6379, db=0)

# Init pipeline
pipeline = None

#def prepare_pipeline(model_name):
    #pipeline = StableDiffusionXLPipeline.from_single_file(
        #model_name, 
        #torch_dtype=torch.float16,  # float16 사용으로 GPU 메모리 효율화
        #variant="fp16"  # 16-bit floating point 사용
    #).to('cuda')
    #return pipeline

def seamless_tiling(pipeline, x_axis, y_axis):
    def asymmetric_conv2d_convforward(self, input: torch.Tensor, weight: torch.Tensor, bias: Optional[torch.Tensor] = None):
        self.paddingX = (self._reversed_padding_repeated_twice[0], self._reversed_padding_repeated_twice[1], 0, 0)
        self.paddingY = (0, 0, self._reversed_padding_repeated_twice[2], self._reversed_padding_repeated_twice[3])
        working = torch.nn.functional.pad(input, self.paddingX, mode=x_mode)
        working = torch.nn.functional.pad(working, self.paddingY, mode=y_mode)
        return torch.nn.functional.conv2d(working, weight, bias, self.stride, torch.nn.modules.utils._pair(0), self.dilation, self.groups)

    # Set padding mode
    x_mode = 'circular' if x_axis else 'constant'
    y_mode = 'circular' if y_axis else 'constant'

    targets = [pipeline.vae, pipeline.text_encoder, pipeline.unet]
    convolution_layers = []
    for target in targets:
        for module in target.modules():
            if isinstance(module, torch.nn.Conv2d):
                convolution_layers.append(module)

    for layer in convolution_layers:
        if isinstance(layer, LoRACompatibleConv) and layer.lora_layer is None:
            layer.lora_layer = lambda * x: 0

        layer._conv_forward = asymmetric_conv2d_convforward.__get__(layer, torch.nn.Conv2d)

    return pipeline

def upload_image_to_minio(image_path, image_name, user_id, prompt_id):
    try:
        # 사용자 ID와 프롬프트 ID를 사용 -> 고유 경로 생성
        folder_path = f"{user_id}/{prompt_id}/"
        full_image_name = folder_path + image_name
        
        # 이미지 파일을 MinIO에 업로드
        minio_client.fput_object(bucket_name, full_image_name, image_path)
        logging.info(f"Image {full_image_name} uploaded to MinIO")
        
        # 업로드된 이미지의 URL 생성
        image_url = minio_client.presigned_get_object(bucket_name, full_image_name)
        return image_url
    except S3Error as e:
        logging.error(f"Error uploading image to MinIO: {e}")
        raise e

@app.task(bind=True, max_retries=0, acks_late=True)
def generate_and_send_image(self, prompt_id, image_data, user_id, options):
    # set pipeline
    try:
        global pipeline
        if pipeline is None:
            pipeline = seamless_tiling(
                pipeline=prepare_pipeline("/mnt/temp/ponyDiffusionV6XL_v6StartWithThisOne.safetensors"), 
                x_axis=True, 
                y_axis=True
            )
            
    except Exception as e:
        logging.error(f"Error in loading pipeline: {e}")
        raise e

    task_id = self.request.id
    start_time = time.time()
    # create image
    try:
        logging.info(f"Received prompt_id: {prompt_id}, user_id: {user_id}, task_id: {task_id}, options: {options}")

        # 임의의 값 설정
        width = options["width"]
        height = options["height"]
        num_inference_steps = options["sampling_steps"]
        guidance_scale = options["cfg_scale"]
        num_images_per_prompt = 4
        seed = options["seed"]  # 고정된 시드를 사용하여 결과를 재현 가능하게 설정
        generator = torch.Generator(device='cuda').manual_seed(seed)

        pos_prompt = "seamless " + image_data["positive_prompt"] + " pattern, fabric textiled pattern"
        neg_prompt = image_data["negative_prompt"] + "irregular shape, deformed, asymmetrical, wavy lines, blurred, low quality, on fabric, real photo, shadow, cracked, text"

        output_dir = '.'

        # Callback 함수 정의
        def progress_callback(pipeline, step, timestep, extra_step_kwargs):
            current_time = time.time()
            elapsed_time = current_time - start_time
            progress_fraction = (step + 1) / num_inference_steps
            progress = progress_fraction * 100  # 퍼센트 계산

            if progress_fraction > 0:
                estimated_total_time = elapsed_time / progress_fraction
                estimated_remaining_time = estimated_total_time - elapsed_time
            else:
                estimated_remaining_time = None

            # 시간을 시, 분, 초로 변환
            if estimated_remaining_time is not None:
                eta_hours, rem = divmod(estimated_remaining_time, 3600)
                eta_minutes, eta_seconds = divmod(rem, 60)
                eta_formatted = f"{int(eta_hours):02d}:{int(eta_minutes):02d}:{int(eta_seconds):02d}"
            else:
                eta_formatted = "Unknown"

            logging.info(f"Step {step + 1}/{num_inference_steps} - Progress: {progress:.2f}% - Estimated remaining time: {eta_formatted}")

            # 진척도와 예상 남은 시간을 Redis에 저장 (Celery 작업 ID를 키로 사용)
            redis_key = f"task_progress:{task_id}"
            redis_data = {
                'progress': progress,
                'estimated_remaining_time': eta_formatted
            }
            redis_client.set(redis_key, json.dumps(redis_data))
            
            # 빈 딕셔너리 반환하여 오류 방지
            return {}

        # Generate images using AI model with progress callback
        images = pipeline(
            prompt=pos_prompt,
            prompt_2="",
            negative_prompt=neg_prompt,
            negative_prompt_2="",
            width=width,
            height=height,
            num_inference_steps=num_inference_steps,
            guidance_scale=guidance_scale,
            num_images_per_prompt=num_images_per_prompt,
            generator=generator,
            callback_on_step_end=progress_callback
        ).images

        for i, image in enumerate(images):
            image_filename = os.path.join(output_dir, f'image_{i+1}.png')
            image.save(image_filename)

            # MinIO에 이미지 업로드 
            image_url = upload_image_to_minio(image_filename, f'image_{i+1}.png', user_id, prompt_id)

            # 데이터베이스에 URL 저장
            result_id = save_image_url_to_database(prompt_id, user_id, image_url)
            logging.info(f"Image {i+1} URL saved to database with result_id: {result_id}")

            os.remove(image_filename)

            logging.info(f"Image {i+1} saved to database with result_id: {result_id}")

        torch.cuda.empty_cache()

        # 성공적으로 이미지 생성 시 추가 처리
        logging.info(f"Images saved successfully with task_id: {task_id}")
        return {"message": "Images saved successfully", "task_id": task_id}

    except Exception as e:
        logging.error(f"Error in generate_and_send_image: {e}")
        raise e


### minio 링크 디비 저장 ###
def save_image_url_to_database(prompt_id, user_id, image_url):
    try:
        connection = mysql.connector.connect(**db_config)
        if connection.is_connected():
            cursor = connection.cursor()

            insert_query = """
            INSERT INTO results (prompt_id, user_id, image_data, created_at) 
            VALUES (%s, %s, %s, %s)
            """
            created_at = datetime.now()
            cursor.execute(insert_query, (prompt_id, user_id, image_url, created_at))
            connection.commit()

            result_id = cursor.lastrowid
            logging.info("Image URL inserted into MySQL database successfully")

            return result_id

    except mysql.connector.Error as e:
        logging.error(f"Error connecting to MySQL: {e}")
        raise e

    finally:
        if connection.is_connected():
            cursor.close()
            connection.close()
            logging.info("MySQL connection closed")

