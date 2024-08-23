"""
Overview
========

This is a connector plugin for interacting with a Slack Workspace.

"""
import asyncio
import logging
import traceback

from datetime import datetime, timezone, timedelta
from functools import wraps
from pprint import pformat
from typing import(
    Dict,
    List,
    Optional,
    Union,
    Tuple,
)

import httpx

from slack_sdk.web.async_client import AsyncWebClient, AsyncSlackResponse
from slack_sdk.errors import SlackApiError

from ledhntr.data_classes import(
    Attribute,
    Entity,
    Relation,
)

from ledhntr.helpers import LEDConfigParser
from ledhntr.helpers import format_date, dumps, xterm
from ledhntr.plugins.connector import ConnectorPlugin

# import os
# _log: logging.Logger = logging.getLogger('ledhntr')
# _log.debug(f"PYTHONPATH: {os.environ.get('PYTHONPATH')}")
# _log.debug(f"Current DIR: {os.path.abspath(__file__)}")
from slack_client.modal_builder import ModalBuilder
from slack_client.modal_builder.helpers import(
    blockaction_update_view,
    get_action_ids,
    get_state_vals_by_type,
    replace_block_by_id
)

#&##########################################################################
#& HELPER FUNCTIONS
#&##########################################################################

_log: logging.Logger = logging.getLogger('ledhntr')

#&##########################################################################
#& COMMON MODAL LAYOUTS
#&##########################################################################




#&##########################################################################
#& DECORATORS
#&##########################################################################

def check_client(func):
    @wraps(func)
    async def check_client_wrapper(self, *args, **kwargs):
        _log = self._log
        if 'channel' in kwargs and kwargs['channel'].startswith('#'):
            kwargs['channel'] = kwargs['channel'].lstrip('#')
        if not self.client:
            # // _log.debug(f"self.client not defined. Reloading client.")
            await self.reload_web_client()
        else:
            _log.debug(f"self.client.auth_test: {await self.client.auth_test()}")
        if not await self.client.auth_test():
            await self.reload_web_client()
        # ! _log.debug(f"{xterm('YELLOW')}Calling {func} with args {args} and kwargs \n{pformat(kwargs)}")
        return await func(self, *args, **kwargs)
    return check_client_wrapper

#&##########################################################################
#& Client
#&##########################################################################

class SlackClient(ConnectorPlugin):
    """SlackClient
    """
    def __init__(
        self,
        config: LEDConfigParser = None,
        logger: Optional[logging.Logger] = None,
    ) -> None:
        super().__init__(config)

        if not logger:
            self._log: logging.Logger = logging.getLogger('ledhntr')
        else:
            self._log = logger
        self.config = config

        self.token = config.get(
            'options',
            'token',
            fallback = '<YOUR_TOKEN>',
        )

        self.cmd = config.get(
            'options',
            'cmd',
            fallback='mojo',
        )

        self.admin_channel = config.get(
            'options',
            'admin_channel',
            fallback='mojo-admin',
        )
        # // if not self.admin_channel.startswith('#'):
        # //     self.admin_channel = f"#{self.admin_channel}"
        self.user_id = config.get(
            'options',
            'user_id',
            fallback='U0000000000',
        )

        self.user_channel = config.get(
            'options',
            'user_channel',
            fallback='mojo',
        )
        # // if not self.user_channel.startswith('#'):
        # //     self.user_channel = f"#{self.user_channel}"

        self.default_db = config.get(
            'options',
            'default_db',
            fallback='scratchpad',
        )

        self.client = None

    def __getstate__(self):
        state = self.__dict__.copy()
        state['client'] = None
        state['log'] = None
        state['_log'] = None
        state['logger'] = None
        return state

    def __setstate__(self, state):
        self.__dict__.update(state)
        self.client = None

    #&##########################################################################
    #& Helpers
    #&##########################################################################
    @staticmethod
    async def blockaction_update_view(
        payload: Dict = None,
    )->Tuple[Dict, List[str], Dict]:
        """Get updated view and selection value

        :param payload: Payload sent by block action when selection is chosen,
            defaults to None
        :type payload: Dict, required
        :return: copied view, selection value or False if invalid
        :rtype: Tuple[Dict, List[str], Dict]
        """
        return await blockaction_update_view(payload=payload)

    @staticmethod
    async def get_action_ids(
        payload: Dict = None,
    )->Union[List[str], False]:
        """Given a block_action or view_submission payload, extract the action_ids

        :param payload: Payload sent by view_submission or block_action, defaults to None
        :type payload: Dict, optional
        :return: list of action_ids passed or False if not block_actions or
            view_submission payload type
        :rtype: Union[List[str], False]
        """
        return await get_action_ids(payload=payload)

    @staticmethod
    async def get_state_vals_by_type(
    data:Dict = None,
    )->Union[None, List[str]]:
        """Retruns values set in payload.view.state.values.block_id.action_id

        :param data: dict pulled from payload.view.state.values.block_id.action_id,
            defaults to None
        :type data: Dict, required
        :return: List of values returend from that single input or None
        :rtype: Union[None, List[str]]
        """
        return await get_state_vals_by_type(data=data)

    @staticmethod
    async def replace_block_by_id(
        old_blocks:List[dict] = None,
        new_block: dict = None,
        old_block_id: Optional[str] = None,
    )->List[Dict]:
        """Replaces a specific block in a list of blocks by matching block_id.

        This function searches through the provided list of old blocks for a block
        with a matching `old_block_id` and replaces it with the `new_block`. If no
        match is found, the original list of blocks is returned unmodified.

        :param old_blocks: List of old blocks where a block needs to be replaced,
            defaults to None
        :type old_blocks: List[dict], required
        :param new_block: New block to insert into the list, defaults to None
        :type new_block: dict, required
        :param old_block_id: The ID of the block to be replaced if different
            from the value in new_block, defaults to None
        :type old_block_id: Optional[str], optional
        :return: Updated list of blocks with the specified block replaced
        :rtype: List[Dict]
        """
        return await replace_block_by_id(
            old_blocks=old_blocks,
            new_block=new_block,
            old_block_id=old_block_id,
        )


    #&##########################################################################
    #& LOAD CLIENT
    #&##########################################################################

    async def reload_web_client(
        self,
        token: Optional[str] = None,
    )->AsyncWebClient:
        """reload web client

        :param token: SlackBot Token, defaults to None
        :type token: Optional[str], optional
        :return: SlackBot WebClient
        :rtype: WebClient
        """
        _log = self._log
        _log.debug(f"Reloading AsyncWebClient...")
        if not token:
            self.client = AsyncWebClient(token=self.token)
            _log.debug(f"Explicit token not set. Using self.token") # : {self.token}")
        else:
            self.client = AsyncWebClient(token=token)
            _log.debug(f"Explicit token set: {token}.")
        return self.client

    #&##########################################################################
    #& HANDLE CHANNELS
    #&##########################################################################

    @check_client
    async def conversations_info(
        self,
        channel: Optional[str] = None,
        **kwargs,
    )->Dict:
        _log.debug(f"Getting channel info for channel: {channel}")
        resp = await self.client.conversations_list(types="public_channel,private_channel", limit=1000)
        convo_list = resp.data['channels']
        if channel is None:
            return convo_list
        for convo in convo_list:
            if convo['name']==channel:
                try:
                    resp = await self.client.conversations_info(
                        channel=convo['id'],
                        **kwargs,
                    )
                    return resp.data['channel']
                except SlackApiError as e:
                    _log.error(
                        f"{xterm('RED')}Error getting conversations info {e.response['error']}"
                        f"{xterm('X')}"
                    )
                    _log.error(f"Traceback: \n{pformat(traceback.format_exc())}")
                    return False
                except Exception as e:
                    _log.error(f"Error getting conversations info: {e}")
                    _log.error(f"Traceback: \n{pformat(traceback.format_exc())}")
                    return False
        _log.debug(f"No channel found called {channel}.")
        return convo_list

    #&##########################################################################
    #& GET USER INFO
    #&##########################################################################

    @check_client
    async def users_info(
        self,
        user_ids: List[str] = None,
        **kwargs
    )->Dict:
        """Retrieve user information from a list of user_ids

        :param user_ids: list of Slack User IDs, defaults to None
        :type user_ids: List[str], required
        :return: Key/val dictionary where the user ID is the keys and the values
            is the data returned
        :rtype: Dict
        """
        rez = {}
        _log = self.log
        # // _log.debug(f"{xterm('BOLD_BLACK')}user_ids: {user_ids}")
        for user_id in user_ids:
            # // _log.debug(f"{xterm('BOLD_BLACK')}user_id: {user_id}")
            # // _log.debug(f"{xterm('BOLD_BLACK')}kwargs: {kwargs}")
            try:
                response = await self.client.users_info(
                    user=user_id,
                    **kwargs,
                )
            except SlackApiError as e:
                _log.error(f"Error getting convo history {e.response['error']} {user_id}")
                continue
            except Exception as e:
                _log.error(f"Error getting convo history: {e}")
                continue

            rez[user_id]=response.data
        # // _log.debug(f"rez: {pformat(rez)}")
        return rez

    #&##########################################################################
    #& HANDLE MESSAGES AND RESPONSES
    #&##########################################################################

    @check_client
    async def action_response(
        self,
        text: str = None,
        response_url: str = None,
        blocks: Optional[List] = None,
        blocks_verbatim: Optional[bool] = False,
        response_type: Optional[str] = "ephemeral",
        **kwargs
    )->bool:
        """Handle responses to various Slack Actions (button clicks, etc)

        :param text: Text to include in the response payload, defaults to None
        :type text: str, optional
        :param response_url: Response URL to send payload to, defaults to None
        :type response_url: str, optional
        :param blocks: Block Kit Blocks for pretty messages, defaults to None
        :type blocks: List, optional:param blocks_verbatim: Verbatim means blocks won't do things like render links
        :type blocks_verbatim: boolean
        :param response_type: Response type, ephemeral or in_channel, defaults to "ephemeral"
        :type response_type: Optional[str], optional
        :return: True if message succeeded, False if it failed
        :rtype: Boolean
        """
        _log = self._log
        if blocks is None:
            blocks = [await ModalBuilder.mrkdwn_block(
                text=text,
                verbatim=blocks_verbatim
            )]
        resp_url = response_url
        resp_payload = {
            "response_type": response_type,
            "text": text,
            "blocks": blocks
        }
        _log.debug(f"Posting {pformat(resp_payload)} to {resp_url}")
        try:
            async with httpx.AsyncClient() as client:
                await client.post(resp_url, json=resp_payload)
            return True
        except Exception as e:
            _log.error(f"Error posting to {resp_url}")
            return False

    @check_client
    async def conversations_history(
        self,
        channel: str = None,
        inclusive: Optional[bool] = None,
        latest: Optional[str] = None,
        limit: Optional[int] = None,
        oldest: Optional[str] = None,
        **kwargs
    )->bool:
        _log = self.log
        try:
            response = await self.client.conversations_history(
                channel=channel,
                inclusive=inclusive,
                latest=latest,
                limit=limit,
                oldest=oldest,
                **kwargs,
            )
        except SlackApiError as e:
            _log.error(f"Error getting convo history {e.response['error']}")
            return False
        except Exception as e:
            _log.error(f"Error getting convo history: {e}")
            return False

        return response.data

    @check_client
    async def conversations_replies(
        self,
        channel: str = None,
        ts: str = None,
        inclusive: Optional[bool] = None,
        latest: Optional[str] = None,
        limit: Optional[int] = None,
        oldest: Optional[str] = None,
        **kwargs
    )->bool:
        _log = self.log
        try:
            response = await self.client.conversations_replies(
                channel=channel,
                ts=ts,
                inclusive=inclusive,
                latest=latest,
                limit=limit,
                oldest=oldest,
                **kwargs,
            )
        except SlackApiError as e:
            _log.error(f"Error getting convo history {e.response['error']}")
            return False
        except Exception as e:
            _log.error(f"Error getting convo history: {e}")
            return False

        return response.data

    @check_client
    async def delete_message(
        self,
        channel: str = None,
        ts: str = None,
        **kwargs,
    )->bool:
        _log.debug(f"Deleting message {ts} from channel {channel}")
        try:
            resp = await self.client.chat_delete(
                channel=channel,
                ts=ts,
                **kwargs
            )
        except SlackApiError as e:
            _log.error(
                f"{xterm('RED')}Error deleting message {e.response['error']}"
                f"{xterm('X')}"
            )
            _log.error(f"Traceback: \n{pformat(traceback.format_exc())}")
            return False
        except Exception as e:
            _log.error(f"Error deleting message: {e}")
            _log.error(f"Traceback: \n{pformat(traceback.format_exc())}")
            return False
        _log.debug(f"Successfully deleted message: {resp.data}")
        return True

    @check_client
    async def post_message(
        self,
        channel: str = None,
        text: str = None,
        blocks: Optional[List] = None,
        blocks_verbatim: Optional[bool] = False,
        ephemeral: Optional[bool] = False,
        thread_ts: Optional[str] = None,
        unfurl_links: Optional[bool] = False,
        unfurl_media: Optional[bool] = False,
        **kwargs
    )->AsyncSlackResponse:
        """Posts brand new message to a channel

        :param channel: Channel or DM ID, defaults to None
        :type channel: str, optional
        :param ephemeral: If set to True, sends an ephemeral message
        :type ephemeral: bool, optional
        :param text: Text to post to the channel, defaults to None
        :type text: str, optional
        :param blocks: Block Kit blocks for pretty messages, defaults to None
        :type blocks: List, optional
        :param blocks_verbatim: Verbatim means blocks won't do things like render links
        :type blocks_verbatim: boolean
        :param thread_ts: Timestamp of original message, used for starting threads
        :type thread_ts: str
        :param unfurl_links: If set to True, unfurls links in the message
        :type unfurl_links: bool, optional
        :param unfurl_media: If set to True, unfurls media attachments in the message
        :type unfurl_media: bool, optional
        :return: True if successful, False if failure
        :rtype: bool
        """
        _log = self._log
        if channel.startswith('#'):
            channel = channel.lstrip('#')
        if blocks is None:
            blocks = [await ModalBuilder.mrkdwn_block(
                text=text,
                verbatim=blocks_verbatim
            )]

        if thread_ts is not None:
            thread_ts = str(thread_ts)

        _log.debug(f"TEXT:{xterm('MAGENTA')} \n{pformat(text)}")
        _log.debug(f"BLOCKS:{xterm('MAGENTA')} \n{pformat(blocks)}")

        def chunk_blocks_by_size(blocks, block_limit, size_limit):
            chunks = []
            current_chunk = []
            current_size = 0

            for block in blocks:
                block_size = len(dumps(block, compactly=True))
                if len(current_chunk) < block_limit and current_size + block_size <= size_limit:
                    current_chunk.append(block)
                    current_size += block_size
                else:
                    chunks.append(current_chunk)
                    current_chunk = [block]
                    current_size = block_size

            if current_chunk:
                chunks.append(current_chunk)

            return chunks

        # Use smaller size limit for thread messages (4K Chars)
        size_limit = 4000 if thread_ts else 10000
        chunked_blocks = chunk_blocks_by_size(blocks, 20, size_limit)
        parse = not blocks_verbatim

        async def send_blocks(blocks_chunk, thread_ts):
            try:
                if ephemeral:
                    response = await self.client.chat_postEphemeral(
                        channel=channel,
                        text=text,
                        blocks=blocks_chunk,
                        thread_ts=thread_ts,
                        parse=parse,
                        unfurl_links=unfurl_links,
                        unfurl_media=unfurl_media,
                        **kwargs,
                    )
                else:
                    response = await self.client.chat_postMessage(
                        channel=channel,
                        text=text,
                        blocks=blocks_chunk,
                        thread_ts=thread_ts,
                        parse=parse,
                        unfurl_links=unfurl_links,
                        unfurl_media=unfurl_media,
                        **kwargs,
                    )
                # // _log.debug(f"{xterm('CYAN')}SUCCESS")
                # // _log.debug(f"num_blocks: {len(blocks_chunk)}")
                # // _log.debug(f"blocks bytes: {len(dumps(blocks_chunk, compactly=True))}")
                # // _log.debug(f"thread_ts: {thread_ts}")
                # // _log.debug(f"blocks: {blocks_chunk}")
                return response
            except SlackApiError as e:
                _log.error(f"SlackError sending message: {e}")
                _log.error(f"ERROR: {e.response['error']}")
                _log.error(f"channel: {channel}")
                # // _log.error(f"text: {text}")
                _log.error(f"num_blocks: {len(blocks_chunk)}")
                _log.error(f"blocks bytes: {len(dumps(blocks_chunk, compactly=True))}")
                # // _log.error(f"blocks: {pformat(blocks_chunk)}")
                _log.error(f"thread_ts: {thread_ts}")
                _log.error(f"parse: {parse}")
                for k, v in kwargs.items():
                    _log.error(f"{k}: {v}")
                _log.error(xterm('X'))
                return False
            except Exception as e:
                _log.error(f"Error sending message: {e}")
                return False

        for i, blocks_chunk in enumerate(chunked_blocks):
            if i == 0:
                response = await send_blocks(blocks_chunk, thread_ts)
                if response is False:
                    return False
                thread_ts = response.data.get('ts')
            else:
                response = await send_blocks(blocks_chunk, thread_ts)
                if response is False:
                    return False

        return response

    @check_client
    async def update_message(
        self,
        channel: str = None,
        ts: str = None,
        text: str = None,
        blocks: Optional[List] = None,
        blocks_verbatim: Optional[bool] = False,
        **kwargs
    )->Union[AsyncSlackResponse, False]:
        """update pre-exising message

        :param channel: channel name where message resides, defaults to None
        :type channel: str, optional
        :param ts: timestamp message was sent, defaults to None
        :type ts: str, optional
        :param text: text to update message with, defaults to None
        :type text: str, optional
        :param blocks: Block Kit blocks for pretty messages, defaults to None
        :type blocks: List, optional
        :return: True if successful, False if failure
        :rtype: Boolean
        """
        _log = self._log
        if blocks is None:
            blocks = [
            {
                'type': 'section',
                'text': {
                    'type': 'mrkdwn',
                    'verbatim': blocks_verbatim,
                    'text': text,
                },
            }
        ]
        try:
            response = await self.client.chat_update(
                channel = channel,
                ts = ts,
                text = text,
                blocks = blocks,
            )
        except SlackApiError as e:
            _log.error(
                f"{xterm('RED')}Error sending message {e.response['error']}"
                f"{xterm('X')}"
            )
            _log.error(f"Traceback: \n{pformat(traceback.format_exc())}")
            return False
        except Exception as e:
            _log.error(f"Error sending message: {e}")
            _log.error(f"Traceback: \n{pformat(traceback.format_exc())}")
            return False

        _log.debug(f"Successful update!: {pformat(response)}")
        return response

    @check_client
    async def upload_snippet(
        self,
        filename:str = None,
        content:str = None,
        title: str = None,
        snippet_type:str = None,
        channel:str = None,
        initial_comment: str = None,
    )->bool:
        _log = self._log
        if channel.startswith('#'):
            channel = channel.lstrip('#')
        try:
            response = await self.client.files_upload_v2(
                channel=channel,
                content=content,
                filename=filename,
                snippet_type=snippet_type,
                title=title,
                initial_comment=initial_comment,
            )
            _log.debug(f"File {filename} successfully uploaded: {response['file']['permalink']}")
            return True
        except SlackApiError as e:
            _log.error(f"Error uploading snippet: {e}")
            _log.error(f"filename: {filename}")
            _log.error(f"content: {content[0:100]}...")
            _log.error(f"title: {title}")
            _log.error(f"snippet_type: {snippet_type}")
            _log.error(f"channel: {channel}")
            _log.error(f"initial_comment: {initial_comment}")
            raise

    #&##########################################################################
    #& HANDLE MODALS
    #&##########################################################################
    @check_client
    async def views_push(
        self,
        trigger_id: str = None,
        view: dict = None,
    )->AsyncSlackResponse:
        """Push a view on top of an existing modal
        """
        _log = self._log
        _log.debug(f"Pushing view...")
        try:
            result = await self.client.views_push(
                trigger_id=trigger_id,
                view=view,
            )
        except SlackApiError as e:
            _log.error(f"Error pushing view: {e}")
            _log.error(f"Traceback: \n{pformat(traceback.format_exc())}")
            return False
        except Exception as e:
            _log.error(f"Error pushing view: {e}")
            _log.error(f"Traceback: \n{pformat(traceback.format_exc())}")
            return False
        return result

    @check_client
    async def views_update(
        self,
        view: dict = None,
        external_id: Optional[str] = None,
        view_id: Optional[str] = None,
        hash: Optional[str] = None,
        **kwargs
    )->AsyncSlackResponse:
        try:
            resp = await self.client.views_update(
                view=view,
                external_id=external_id,
                view_id=view_id,
                hash=hash,
                **kwargs
            )
        except SlackApiError as e:
            raise
        except Exception as e:
            raise
        return resp

    @check_client
    async def views_open(
        self,
        trigger_id: str = None,
        view: List = None,
        **kwargs
    )->None:
        try:
            result = await self.client.views_open(
                trigger_id=trigger_id,
                view=view,
                **kwargs
            )
        except SlackApiError as e:
            raise
        except Exception as e:
            raise
        return result

    #~########################
    #~ INVALID COMMAND POPUP
    #~########################

    @check_client
    async def invalid_command(
        self,
        trigger_id: str = None,
        cmd: str = None,
        **kwargs
    )->None:
        _log = self._log
        view = await ModalBuilder.invalid_command_modal(cmd=cmd)
        try:
            result = await self.client.views_open(
                trigger_id=trigger_id,
                view=view,
            )
        except Exception as e:
            _log.error(f"Error opening invalid command modal: {e}")
            _log.error(f"Traceback: \n{pformat(traceback.format_exc())}")
            return False
        _log.debug(f"result: {result}")
        return result

    #~########################
    #~ UNAUTHORIZED POPUP
    #~########################

    @check_client
    async def unauthorized_resp(
        self,
        trigger_id: str = None,
        **kwargs
    )->None:
        _log = self._log
        _log.debug(f"Unauthorized operation.")
        result = await self.client.views_open(
            trigger_id=trigger_id,
            view=await ModalBuilder.unauthorized_modal(),
        )
        _log.debug(f"result: {result}")
        return result

    #&##########################################################################
    #& INTERACTIVITY
    #& Slack Actions, Slack Events, and Slash-Commands
    #&##########################################################################
