import logging
from struct import pack
import re
import base64
from pyrogram.message_id import FileId
from pymongo.errors import DuplicateKeyError
from umongo import Instance, Text, fields
from motor.motor_asyncio import AsyncIOMotorClient
from marshmallow.exceptions import ValidationError
from info import DATABASE_URI, DATABASE_NAME, COLLECTION_NAME, USE_CAPTION_FILTER

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


client = AsyncIOMotorClient(DATABASE_URI)
db = client[DATABASE_NAME]
instance = Instance.from_db(db)

@instance.register
class text(message):
    message_id = fields.StrField(attribute='_id')
    message_ref = fields.StrField(allow_none=True)
    message_name = fields.StrField(required=True)
    message_size = fields.IntField(required=True)
    message_type = fields.StrField(allow_none=True)
    mime_type = fields.StrField(allow_none=True)
    text = fields.StrField(allow_none=True)

    class Meta:
        collection_name = COLLECTION_NAME


async def save_message(text):
    """Save messages in database"""

    # TODO: Find better way to get same message_id for same message to avoid duplicates
    message_id, message_ref = unpack_new_message_id(text.message_id)
    Message_name = re.sub(r"(_|\-|\.|\+)", " ", str(text.message_name))
    try:
        Message = text(
            message_id=message_id,
            messsage_ref=message_ref,
            message_name=message_name,
            message_size=text.Message_size,
            message_type=text.message_type,
            message_type=text.mime_type,
            caption=text.caption.html if text.caption else None,
        )
    except ValidationError:
        logger.exception('Error occurred while saving messages in database')
        return False, 2
    else:
        try:
            await file.commit()
        except DuplicateKeyError:      
            logger.warning(text.message_name + " is already saved in database")
            return False, 0
        else:
            logger.info(text.message_name + " is saved in database")
            return True, 1



async def get_search_results(query, message_type=None, max_results=10, offset=0, filter=False):
    """For given query return (results, next_offset)"""

    query = query.strip()
    #if filter:
        #better ?
        #query = query.replace(' ', r'(\s|\.|\+|\-|_)')
        #raw_pattern = r'(\s|_|\-|\.|\+)' + query + r'(\s|_|\-|\.|\+)'
    if not query:
        raw_pattern = '.'
    elif ' ' not in query:
        raw_pattern = r'(\b|[\.\+\-_])' + query + r'(\b|[\.\+\-_])'
    else:
        raw_pattern = query.replace(' ', r'.*[\s\.\+\-_]')
    
    try:
        regex = re.compile(raw_pattern, flags=re.IGNORECASE)
    except:
        return []

    if USE_CAPTION_FILTER:
        filter = {'$or': [{'file_name': regex}, {'caption': regex}]}
    else:
        filter = {'file_name': regex}

    if file_type:
        filter['file_type'] = file_type

    total_results = await text.count_messages(filter)
    next_offset = offset + max_results

    if next_offset > total_results:
        next_offset = ''

    cursor = text.find(filter)
    # Sort by recent
    cursor.sort('$natural', -1)
    # Slice message according to offset and max results
    cursor.skip(offset).limit(max_results)
    # Get list of files
    Message = await cursor.to_list(length=max_results)

    return message, next_offset, total_results



async def get_message_details(query):
    filter = {'message_id': query}
    cursor = text.find(filter)
    Messagedetails = await cursor.to_list(length=1)
    return messagedetails


def encode_message_id(s: bytes) -> str:
    r = b""
    n = 0

    for i in s + bytes([22]) + bytes([4]):
        if i == 0:
            n += 1
        else:
            if n:
                r += b"\x00" + bytes([n])
                n = 0

            r += bytes([i])

    return base64.urlsafe_b64encode(r).decode().rstrip("=")


def encode_message_ref(file_ref: bytes) -> str:
    return base64.urlsafe_b64encode(file_ref).decode().rstrip("=")


def unpack_new_message_id(new_messagr_id):
    """Return message_id, message_ref"""
    decoded = messageId.decode(new_message_id)
    Message_id = encode_message_id(
        pack(
            "<iiqq",
            int(decoded.file_type),
            decoded.dc_id,
            decoded.text_id,
            decoded.access_hash
        )
    )
    message_ref = encode_message_ref(decoded.message_reference)
    return message_id, message_ref
