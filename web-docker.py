from flask import Flask,render_template,request
import os
import json
import docker

client = docker.from_env()
app = Flask(__name__)

@app.route("/")
def home():
    return render_template('index.html')

@app.route("/submit",methods=['GET','POST'])
def submit():
    addcap = ''
    dropcap = ''
    dropsys = 'unconfined'
    ls = []
    if request.method == "POST":
        if(len(request.form.getlist('addc'))):  #add capabilities
            ls=(request.form.getlist('addc'))
            for i in ls:
                addcap = addcap + '--cap-add ' + i + ' '
        if(len(request.form.getlist('dropc'))): #drop capabilities
            ls=(request.form.getlist('dropc'))
            for i in ls:
                dropcap = dropcap + '--cap-drop ' + i + ' '
    
        if(len(request.form.getlist('drops'))): #drop systemcalls
            ls+=(request.form.getlist('drops'))
            str1 = """{
            "defaultAction": "SCMP_ACT_ALLOW",
            "syscalls":  [
                """
            count = len(ls)-1
            for i in ls:
                str1+= """{
                    "name": "%s",
                    "action": "SCMP_ACT_KILL",
                    "args": []
                }"""%i
                if(count):
                    count-=1
                    str1+=""",
                """
            str1+="""
            ]
            }"""
            file = open('profile.json','w')
            file.write(str1)
            file.close()
            dropsys = 'profile.json'
    os.system("docker run -d {} {} --security-opt seccomp={} alpine sleep 300".format(addcap,dropcap,dropsys))
    return render_template('container.html')

app.run(debug=True)
