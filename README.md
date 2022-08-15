# django-pims
个人私密信息管理系统

## 说明
程序基于django 3.2 开发，用于管理个人一些私密信息。

程序想要解决的问题：
现在是个信息化社会，有太多的信息需要记忆，有太多的密码久了未用就遗忘了，怎么办，写在纸上？电脑中找个私密地方存储在文件中？感觉不方便，也不安全。
本程序能让你比较安全地将这些信息存储在电脑中，只有拥有保护口令才能查看相关信息。

信息分为三个等级存储：
明文，用于存储需要记忆但不重要的信息。
普通，用于存储有一定私密性，需要加密存储的信息。
重要，用于存储银行、证券等重要信息，也是加密存储。

免责声明：
本程序能加密存储需要保护的信息，但加密信息并非绝对安全，只要时间足够依然会有被破解的风险。
本软件为非盈利软件，作者没有义务也没有责任对用户使用软件带来的任何损失或风险承担任何责任。

## 目录说明
```
dist 打包文件输出目录：django-pims-1.0.1.tar.gz 
private_info: 代码文件目录，对应django中的app。
setup.py 用于打包本项目。
```

## 快速开始
### 1. win10 虚拟环境安装
安装python3.6 或以上版本。
准备虚拟环境：python -m venv d:\py-venv
cd /d d:\py-venv\Scripts
activate

进入虚拟环境后，提示符如下：
(py-venv) d:\py-venv\Scripts>

拷贝文件：django-pims-1.0.1.tar.gz 到 d:\py-venv
(py-venv) d:\py-venv>pip install django-pims-1.0.1.tar.gz

依赖包会同时下载安装，安装完成后可用 pip list 查看。
```
(py-venv) d:\py-venv>pip list
Package        Version
-------------- -------
asgiref        3.5.2
Django         4.1
django-pims    1.0.1
gmssl          3.2.1
pip            22.0.4
python-version 0.0.2
setuptools     58.1.0
sqlparse       0.4.2
tzdata         2022.1

```

### 2. 创建 django 项目

(py-venv) d:\py-venv>django-admin startproject pims



### 3. 编辑 settings.py
```
cd pims\pims 
py-venv) d:\py-venv\pims\pims>dir

2022/08/07  10:51    <DIR>          .
2022/08/07  10:51    <DIR>          ..
2022/08/07  10:51               401 asgi.py
2022/08/07  10:57             3,483 settings.py
2022/08/07  10:58             1,111 urls.py
2022/08/07  10:51               401 wsgi.py
2022/08/07  10:51                 0 __init__.py
               5 个文件          5,396 字节
               2 个目录 767,041,609,728 可用字节
			   

用文本编辑工具或开发工具打开文件：settings.py 

按下面描述修改文件内容：		   

\# 导入信息管理模块
import private_info  

INSTALLED_APPS = [
    'private_info.apps.PrivateInfoConfig',  # 注册信息管理应用
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
]



\# 修改时区设置
LANGUAGE_CODE = 'zh-hans'
TIME_ZONE = 'Asia/Shanghai'
USE_I18N = True
USE_L10N = True
USE_TZ = True


\# 设置登录后访问页面。
LOGIN_REDIRECT_URL = "/pims/data/simple/"  

```

### 3. 编辑 urls.py
```

from django.contrib import admin
from django.urls import include, path
from django.contrib.auth import views as auth_views

import private_info


urlpatterns = [
    path('admin/', admin.site.urls),
    path('login/', auth_views.LoginView.as_view(template_name='private_info/login.html'), name='login'),
    path('', auth_views.LoginView.as_view(template_name='private_info/login.html'), name='login'),
    path('pims/', include('private_info.urls'))
]


### 4. 创建应用模型数据
cd /d d:\py-venv\pims

生成数据表结构：
(py-venv) d:\py-venv\pims>python manage.py migrate
Operations to perform:
  Apply all migrations: admin, auth, contenttypes, private_info, sessions
Running migrations:
  Applying contenttypes.0001_initial... OK
  Applying auth.0001_initial... OK
  Applying admin.0001_initial... OK
  Applying admin.0002_logentry_remove_auto_add... OK
  Applying admin.0003_logentry_add_action_flag_choices... OK
  Applying contenttypes.0002_remove_content_type_name... OK
  Applying auth.0002_alter_permission_name_max_length... OK
  Applying auth.0003_alter_user_email_max_length... OK
  Applying auth.0004_alter_user_username_opts... OK
  Applying auth.0005_alter_user_last_login_null... OK
  Applying auth.0006_require_contenttypes_0002... OK
  Applying auth.0007_alter_validators_add_error_messages... OK
  Applying auth.0008_alter_user_username_max_length... OK
  Applying auth.0009_alter_user_last_name_max_length... OK
  Applying auth.0010_alter_group_name_max_length... OK
  Applying auth.0011_update_proxy_permissions... OK
  Applying auth.0012_alter_user_first_name_max_length... OK
  Applying private_info.0001_initial... OK
  Applying private_info.0002_auto_20220726_1419... OK
  Applying private_info.0003_auto_20220728_1548... OK
  Applying private_info.0004_auto_20220729_2008... OK
  Applying sessions.0001_initial... OK
  
```
### 5. 开始服务（个人使用无需部署，直接用django提供的web服务也能满足需求）
```
cd /d d:\py-venv\pims

开始服务：
((py-venv) d:\py-venv\pims>python manage.py runserver
Watching for file changes with StatReloader
Performing system checks...

System check identified no issues (0 silenced).
August 07, 2022 - 11:07:05
Django version 4.1, using settings 'pims.settings'
Starting development server at http://127.0.0.1:8000/
Quit the server with CTRL-BREAK.
```

### 6. 访问服务
http://127.0.0.1:8000/


### 7.使用信息管理系统
```
首先需要注册一个用户，登录后设置超级密码、明文密码、普通密码、重要密码。
然后可以根据要保存的信息的重要级别分别管理。

超级密码：用于加密存储其他口令，口令丢失无法找回，只能通过提示信息回忆口令，超级口令可以修改。
明文密码：用于保护明文信息，添加、修改、删除明文信息需要输入明文密码。
普通密码：用于保护普通信息，添加、修改、删除、查看普通信息需要输入普通密码。
重要密码：用于保护重要信息，添加、修改、删除、查看重要信息需要输入重要密码。
明文、普通、重要密码如果遗忘可以通过超级密码查看。


```




