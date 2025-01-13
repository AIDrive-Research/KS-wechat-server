import base64
import json

from flask import Blueprint, request

from app import url_prefix
import xml.etree.cElementTree as ET
bp = Blueprint('alert', __name__, url_prefix=url_prefix)



from WXBizMsgCrypt3 import WXBizMsgCrypt

sToken = 'WAeNTramHtkNKD8w'  
sEncodingAESKey = 'GO2DRNPbFPHMi8jjxCkGJDwwjtrc4IxP6hZx0FsVyKf' 
sReceiveId = 'wwceab37c65d2afc44'  
wxcpt = WXBizMsgCrypt(sToken, sEncodingAESKey, sReceiveId)


@bp.route('alert', methods=['POST','GET'])
def wechat():
    msg_signature = request.args.get('msg_signature')  # 企业微信加密签名
    timestamp = request.args.get('timestamp')  # 时间戳
    nonce = request.args.get('nonce')  # 随机数
    echostr = request.args.get('echostr')  # 加密字符串

    # 验证URL有效性
    if request.method == 'GET':
        ret, sReplyEchoStr = wxcpt.VerifyURL(msg_signature, timestamp, nonce, echostr)
        if ret == 0:
            return sReplyEchoStr
        else:
            return 'ERR: VerifyURL ret:' + str(ret)

    # 接收消息
    if request.method == 'POST':
        ret, xml_content = wxcpt.DecryptMsg(request.data, msg_signature, timestamp, nonce)
        print(xml_content)
        if ret == 0:
            root = ET.fromstring(xml_content)
            print(xml_content)
            to_user_name = root.find('ToUserName').text
            from_user_name = root.find('FromUserName').text
            create_time = root.find('CreateTime').text
            msg_type = root.find('MsgType').text
            return 'ok'
        else:
            return 'ERR: DecryptMsg ret:' + str(ret)
