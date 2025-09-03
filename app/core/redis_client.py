import redis
from decouple import config

REDIS_HOST = config("REDIS_HOST", default="localhost")
REDIS_PORT = config("REDIS_PORT", cast=int, default=6379)
REDIS_DB = config("REDIS_DB", cast=int, default=0)

redis_client = redis.StrictRedis(
    host=REDIS_HOST,
    port=REDIS_PORT,
    db=REDIS_DB,
    decode_responses=True  
)
