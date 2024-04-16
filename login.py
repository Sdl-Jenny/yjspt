import json
import requests
import time
import base64
from PIL import Image
from io import BytesIO
import cv2
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from base64 import b64encode
from urllib.parse import quote


#这里取一下日期时间戳
timestamp_sec = time.time()
timestamp_ms = int(timestamp_sec * 1000)

#这里写学号
student_ID = ""
#这里写密码
password = ""
def extract_between(text, start, end):
    # 尝试分割字符串
    try:
        # 分割得到起始标志后的内容
        result = text.split(start, 1)[1]
        # 分割得到结束标志前的内容
        result = result.split(end, 1)[0]
    except IndexError:
        # 如果start或end不存在，则返回空字符串
        return ""
    return result

def save_base64_image(base64_string, image_path):
    image_data = base64.b64decode(base64_string)
    image = Image.open(BytesIO(image_data))
    image.save(image_path)

def identify_gap(bg, tp, out):

    bg_img = cv2.imread(bg)
    tp_img = cv2.imread(tp)
    bg_edge = cv2.Canny(bg_img, 100, 200)
    tp_edge = cv2.Canny(tp_img, 100, 200)
    bg_pic = cv2.cvtColor(bg_edge, cv2.COLOR_GRAY2RGB)
    tp_pic = cv2.cvtColor(tp_edge, cv2.COLOR_GRAY2RGB)
    res = cv2.matchTemplate(bg_pic, tp_pic, cv2.TM_CCOEFF_NORMED)
    min_val, max_val, min_loc, max_loc = cv2.minMaxLoc(res)
    th, tw = tp_pic.shape[:2]
    tl = max_loc
    br = (tl[0] + tw, tl[1] + th)
    cv2.rectangle(bg_img, tl, br, (0, 0, 255), 2)
    cv2.imwrite(out, bg_img)
    return tl[0]

session = requests.Session()
url = "https://ids.xidian.edu.cn/authserver/login?service=https%3A%2F%2Fyjspt.xidian.edu.cn%2Fgsapp%2Fsys%2Fyjsemaphome%2Fportal%2Findex.do"
response = session.get(url).text
salt = extract_between(response,'id="pwdEncryptSalt" value="','"')
execution = extract_between(response,'name="execution" value="','"')


def slide_png():
    # 获取滑动图片
    url = "https://ids.xidian.edu.cn/authserver/common/openSliderCaptcha.htl?_=" + str(timestamp_ms)
    response = session.get(url).json()
    save_base64_image(response['smallImage'], "smallImage.png")
    save_base64_image(response['bigImage'], "bigImage.png")
    # 开始滑动
    moveLength = (280 * identify_gap('bigImage.png', 'smallImage.png', "sunci.png") / 590)

    # 发送滑动请求
    url = "https://ids.xidian.edu.cn/authserver/common/verifySliderCaptcha.htl"
    data = "canvasLength=280&moveLength=" + str(moveLength) + "0370864868164"
    headers = {
        'Accept': 'application/json, text/javascript, */*; q=0.01',
        'Accept-Encoding': 'gzip, deflate, br, zstd',
        'Accept-Language': 'zh-CN,zh;q=0.9',
        'Connection': 'keep-alive',
        'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8',
        'Origin': 'https://ids.xidian.edu.cn',
        'Referer': 'https://ids.xidian.edu.cn/authserver/login?service=https%3A%2F%2Fyjspt.xidian.edu.cn%2Fgsapp%2Fsys%2Fyjsemaphome%2Fportal%2Findex.do',
        'User-Agent': 'Mozilla/5.0 (Linux; Android 6.0; Nexus 5 Build/MRA58N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Mobile Safari/537.36',
        'X-Requested-With': 'XMLHttpRequest',
        'sec-ch-ua': '"Google Chrome";v="123", "Not:A-Brand";v="8", "Chromium";v="123"',
        'sec-ch-ua-mobile': '?1',
        'sec-ch-ua-platform': '"Android"',
    }
    response = session.post(url=url, data=data, headers=headers).text
    return response



def run_until_success():
    while True:
        result = slide_png()

        if "success" in result:

            break
        time.sleep(1)

run_until_success()

# 滑动结束 开始密码算法

def encrypt_data(data, key, iv):
    # 将字符串键和IV编码为字节
    key_bytes = key.encode('utf-8')
    iv_bytes = iv.encode('utf-8')

    # 创建一个新的 AES cipher 实例
    cipher = AES.new(key_bytes, AES.MODE_CBC, iv_bytes)

    # 将数据编码为字节，然后使用 PKCS7 填充
    data_bytes = data.encode('utf-8')
    padded_data = pad(data_bytes, AES.block_size)

    # 加密数据
    encrypted = cipher.encrypt(padded_data)

    # 将加密的字节转换为 Base64 编码的字符串
    encrypted_base64 = b64encode(encrypted).decode('utf-8')

    return encrypted_base64

data = "jzhCDKD8c33tGbi2etcjNKJH5rFeFMcWX7hRkpKxKRAT2WYtjb66Nkmwz7ab4bTi"+password
key = salt
iv = "xhiK23cawNMMhD5B"
encrypted_output = encrypt_data(data, key, iv)


url = "https://ids.xidian.edu.cn/authserver/login?service=https%3A%2F%2Fyjspt.xidian.edu.cn%2Fgsapp%2Fsys%2Fyjsemaphome%2Fportal%2Findex.do"
data = "username="+student_ID+"&password="+quote(encrypted_output)+"&captcha=&_eventId=submit&lt=&cllt=userNameLogin&dllt=generalLogin&execution="+execution
headers = {
'sec-ch-ua': '";Not A Brand";v="99", "Chromium";v="94"',
'sec-ch-ua-mobile': '?1',
'sec-ch-ua-platform': '"Android"',
'Upgrade-Insecure-Requests': '1',
'Origin': 'https://ids.xidian.edu.cn',
'Content-Type': 'application/x-www-form-urlencoded',
'User-Agent': 'Mozilla/5.0 (Linux; Android 6.0; Nexus 5 Build/MRA58N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/94.0.4606.71 Mobile Safari/537.36',
'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
'Sec-Fetch-Site': 'same-origin',
'Sec-Fetch-Mode': 'navigate',
'Sec-Fetch-User': '?1',
'Sec-Fetch-Dest': 'document',
'Referer': 'https://ids.xidian.edu.cn/authserver/login?service=https%3A%2F%2Fyjspt.xidian.edu.cn%2Fgsapp%2Fsys%2Fyjsemaphome%2Fportal%2Findex.do',
'Accept-Encoding': 'gzip, deflate, br',
'Accept-Language': 'zh-CN,zh;q=0.9'
}
response = session.post(url = url,data=data,headers=headers).text
if "滑块验证码" in response:
    print("登陆失败，请检查账号密码！！")
else:
    url = "https://yjspt.xidian.edu.cn/gsapp/sys/yjsemaphome/modules/pubWork/getUserInfo.do"
    response = session.post(url).text
    data = json.loads(response)

    # 访问 userName 字段
    user_name = data['data']['userName']
    print("胡门孙辞欢迎"+user_name+"的到来！！")
