from bson import ObjectId
from bson.errors import InvalidId


def oid_str(oid: ObjectId | str) -> str:
    return str(oid)


def parse_oid(s: str) -> ObjectId:
    try:
        return ObjectId(s)
    except InvalidId as e:
        raise ValueError("invalid id") from e
