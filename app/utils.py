from pydantic import BaseModel, create_model
from sqlalchemy.orm import class_mapper

def sqlalchemy_to_pydantic(model, name=None):
    mapper = class_mapper(model)
    fields = {
        column.key: (column.type.python_type, ...)
        for column in mapper.columns
    }
    pydantic_model = create_model(name or model.__name__, **fields)
    return pydantic_model
