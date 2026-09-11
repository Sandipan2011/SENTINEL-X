from backend.database.database import Base, engine
from backend.database.models import AlertModel


def initialize_database():
    print("[DATABASE] Creating tables...")

    Base.metadata.create_all(bind=engine)

    print("[DATABASE] Tables created successfully.")


if __name__ == "__main__":
    initialize_database()