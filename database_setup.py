from sqlalchemy import Column, ForeignKey, Integer, String, Text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy import create_engine


Base = declarative_base()


class User(Base):
    __tablename__ = 'user'

    id = Column(Integer, primary_key=True)
    provider = Column(Integer, nullable=False)
    name = Column(String(100), nullable=False)
    email = Column(String(100), nullable=False)
    picture = Column(String(200))


class Category(Base):
    __tablename__ = 'category'

    id = Column(Integer, primary_key=True)
    name = Column(String(100), nullable=False)


class Product(Base):
    __tablename__ = 'product'

    id = Column(Integer, primary_key=True)
    name = Column(String(100), nullable=False)
    description = Column(Text)
    image = Column(String(100))
    cat_id = Column(Integer, ForeignKey('category.id'))
    owner_id = Column(Integer, ForeignKey('user.id'))
    category = relationship(Category)
    user = relationship(User)

    @property
    def serialize(self):
        """ Returns object data in easily serializable format
        """
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'image': self.image,
            'cat_id': self.cat_id,
            'owner_id': self.owner_id
        }


engine = create_engine('sqlite:///catalog.db')

Base.metadata.create_all(engine)