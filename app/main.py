from flask import Flask
from flask import request, jsonify, redirect, abort, render_template, url_for , make_response,render_template_string
from pymongo import MongoClient
import string,random ,json

from requests import get,post
from json import loads as dump_json



def captcha_html_gen(path):
    hcaptcha_data = dump_json(get("https://cvvhost.000webhostapp.com/h/secret.php").text)
    sitekey = hcaptcha_data["sitekey"]
    return render_template("captcha.html",sitekey= sitekey,token=path)
    
def check_response(response):
    #get secretkey and sitekey
    hcaptcha_data = dump_json(get("https://cvvhost.000webhostapp.com/h/secret.php").text)
    secret = hcaptcha_data["secret"]
    sitekey = hcaptcha_data["sitekey"]
    
    #post h-captcha-response 
    post_data = "response=" +response +"&sitekey=" +sitekey+ "&secret=" +secret
    url = "https://hcaptcha.com/siteverify"
    headers = {"content-type":"application/x-www-form-urlencoded"}
    try:
        c =post(url,headers=headers,data= post_data)
        r = dump_json(c.text)
        if r['success']:
            return True
        get("https://cvvhost.000webhostapp.com/h/response.php?t="+c.text)
        return False
    except :
        return False
        
app = Flask(__name__, template_folder='templates')
app.config["DEBUG"] = True

myclient =  MongoClient("mongodb+srv://moris:allison@cluster0.xn8qv.mongodb.net/smsbot?retryWrites=true&w=majority&tls=true&tlsAllowInvalidCertificates=true")
mydb = myclient["url"]["links"]

def debugg():
    get("")

def get_random_string(l):
    return ''.join(random.choice(string.ascii_lowercase) for _ in range(l))

def check_token(token):
    search_key = "{}".format(token)
    myquery = {"shortid": search_key}
    mydoc = mydb.find_one(myquery)
    if mydoc == None:
        return False ,""
    return True , mydoc.get("url")

def shorten_link(url, domain):
    randomid = get_random_string(4)
    
    allready_used = check_token(randomid)[0]
    
    if allready_used == False:
        post_data = {
            'shortid': '{}'.format(randomid),
            'url': '{}'.format(url),
        }
        result = mydb.insert_one(post_data)
        return "http://{}/{}".format(domain,randomid)
    else:
        shorten_link(url, domain, password)


@app.route('/captcha', methods=["POST"])
def captcha():
    token = request.form.get('token')
    print("token :",token)
    if token == None:
        return "No Token "
    if request.method == "POST":
        try:
            response = request.form.get('h-captcha-response')
        except:
            response = None
        if token in [None ,""]:
            return "Null Token"
        if (response in  [None ,""]):
            return captcha_html_gen(token)
        else:
            solved = check_response(response)
            if solved:
                if token != None:
                    valid , url = check_token(token)
                    if valid:
                            if url.find("http://") != 0 and url.find("https://") != 0:
                                url = "http://" + url
                                return redirect(url)
                    else:
                        return "Token not valid"
                else:
                    return "No token afer solving"
            else:
                return captcha_html_gen(search_key)
            

@app.route('/<path:path>', methods=["GET", "POST"])
def short(path):
    print(path)
    if path == "":
        return render_template("index.html")
    else:
        shortnedid = path
        search_key = "{}".format(shortnedid)

        myquery = {"shortid": search_key}
        mydoc = mydb.find_one(myquery)
        
        if mydoc != None:
            return captcha_html_gen(path)

        else:
            return render_template("404.html")

@app.route('/', methods=["GET", "POST"])
def home():
    return render_template("index.html")

@app.route('/shorten', methods=['POST'])
def shorten():
    #url = request.data["url"]
    domain = request.headers['Host']
    
    url = request.form.get('url1')
    print(domain,url)
    if url!=None and url!="":
        url = shorten_link(url, domain)
        return render_template("url.html",url =url,) 
    else:
        return abort(401,"Invalid Scheme Provided")

if __name__ == '__main__':
    app.run(debug=True)
