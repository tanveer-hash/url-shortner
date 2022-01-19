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


@app.route('/captcha', methods=["GET","POST"])
def captcha():
    search_key = request.form.get('token')
    t_cookie = request.cookies.get('s')
    print("token :",search_key,"Cookie :",t_cookie)
    if (search_key == None) and ( t_cookie == None):
        return render_template("404.html")
    if request.method == "GET":
        return captcha_html_gen(t_cookie)
    elif request.method == "POST":
        search_key = request.form.get('token')
        try:
            response = request.form.get('h-captcha-response')
        except:
            response = None
        if search_key in [None ,""]:
            return render_template("404.html")
        if (response in  [None ,""]):
            return captcha_html_gen(search_key)
        else:
            solved = check_response(response)
            if solved:
                if search_key != None:
                    valid , url = check_token(search_key)
                    if valid:
                            if url.find("http://") != 0 and url.find("https://") != 0:
                                url = "http://" + url
                                return redirect(url)
                    else:
                        return render_template("404.html")
                else:
                    return render_template("404.html")
            else:
                return captcha_html_gen(search_key)
            return render_template("404.html")

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
            resp = make_response(captcha_html_gen(path))
            resp.set_cookie("s",search_key)
            return resp

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
