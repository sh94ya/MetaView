from sqlalchemy import MetaData, create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm import Session
from workspace.models.migration import create_tables
import configparser
import os

#Read config file
current_dir = os.path.dirname(os.path.abspath(__file__))
config_path = os.path.join(current_dir, '..', 'config.ini')

config = configparser.ConfigParser()
config.read(config_path)

db_string = "postgresql://{login}:{password}@{address}:{port}/{db}".format(login=config.get("DB", "LOGIN"),
                                                                           password=config.get("DB", "PASSWORD"),
                                                                           address=config.get("DB", "ADDRESS"),
                                                                           port=config.get("DB", "PORT"),
                                                                           db=config.get("DB", "DATABASE"))

db = create_engine(db_string, echo=True)
meta = MetaData(schema="public")  
create_tables(db)


#Create Session
def create_session():
    return Session(db)