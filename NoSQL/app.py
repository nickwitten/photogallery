#!flask/bin/python
import sys, os
sys.path.append(os.path.abspath(os.path.join('..', 'utils')))
from env import *
from flask import Flask, jsonify, abort, request, make_response, url_for
from flask import render_template, redirect
import time
import exifread
import json
import uuid
import boto3  
from boto3.dynamodb.conditions import Key, Attr
import pymysql.cursors
from datetime import datetime
import pytz

"""
    INSERT NEW LIBRARIES HERE (IF NEEDED)
"""

import bcrypt
from itsdangerous import URLSafeTimedSerializer
from botocore.exceptions import ClientError
from flask import session
from datetime import timedelta

"""
"""

app = Flask(__name__, static_url_path="")

dynamodb = boto3.resource('dynamodb', aws_access_key_id=AWS_ACCESS_KEY,
                            aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
                            region_name=AWS_REGION)

table = dynamodb.Table(DYNAMODB_TABLE)
"""
    Added Global Configurations
"""
serializer = URLSafeTimedSerializer(URL_KEY)
user_table = dynamodb.Table(USER_DYNAMODB_TABLE)
app.config['SECRET_KEY'] = FLASK_SECRET_KEY
app.permanent_session_lifetime = timedelta(minutes=10)

"""
"""

UPLOAD_FOLDER = os.path.join(app.root_path,'static','media')
ALLOWED_EXTENSIONS = set(['png', 'jpg', 'jpeg'])

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def getExifData(path_name):
    f = open(path_name, 'rb')
    tags = exifread.process_file(f)
    ExifData={}
    for tag in tags.keys():
        if tag not in ('JPEGThumbnail', 'TIFFThumbnail', 'Filename', 'EXIF MakerNote'):
            key="%s"%(tag)
            val="%s"%(tags[tag])
            ExifData[key]=val
    return ExifData

def s3uploading(filename, filenameWithPath, uploadType="photos"):
    s3 = boto3.client('s3', aws_access_key_id=AWS_ACCESS_KEY,
                            aws_secret_access_key=AWS_SECRET_ACCESS_KEY)
                       
    bucket = PHOTOGALLERY_S3_BUCKET_NAME
    path_filename = uploadType + "/" + filename

    s3.upload_file(filenameWithPath, bucket, path_filename)  
    s3.put_object_acl(ACL='public-read', Bucket=bucket, Key=path_filename)
    return f'''http://{PHOTOGALLERY_S3_BUCKET_NAME}.s3.amazonaws.com/{path_filename}'''


"""
    INSERT YOUR NEW FUNCTION HERE (IF NEEDED)
"""

def read_user_attr(username, attr):
    """ Get an attribute from a specified user """
    try:
        response = user_table.scan(FilterExpression=Attr('username').eq(username))
        return response['Items'][0][attr]
    except:
        return False

def write_user_attr(username, attr, value):
    """ Set the validated attribute for a user to True """
    key={
        'username': username,
    }
    try:
        response = user_table.update_item(
            Key=key,
            UpdateExpression=f'SET {attr}=:v',
            ExpressionAttributeValues={
                ':v': value,
            },
            ReturnValues='UPDATED_NEW',
        )
        return True
    except Exception as e:
        print(e)
        return False

def write_photo_attr(photoID, attr, value):
    """ Set the validated attribute for a user to True """
    response = table.scan(FilterExpression=Attr('photoID').eq(photoID))
    item = response['Items'][0]
    key={
        'albumID': item['albumID'],
        'photoID': photoID,
    }
    try:
        response = table.update_item(
            Key=key,
            UpdateExpression=f'SET {attr}=:v',
            ExpressionAttributeValues={
                ':v': value,
            },
            ReturnValues='UPDATED_NEW',
        )
        return True
    except Exception as e:
        print(e)
        return False

def create_user(user):
    """ Checks database for existing username and/or email.  If
        none exists, create a new user in the database
    """
    try:
        username_response = user_table.scan(FilterExpression=Attr('username').eq(user['username']))
        email_response = user_table.scan(FilterExpression=Attr('email').eq(user['email']))
        if username_response['Count'] > 0 or email_response['Count'] > 0:
            # Username or email already exists
            print("User exists")
            return False
        user_table.put_item(Item=user)
        return True
    except Exception as e:
        return False

def delete_picture(photoID):
    """ Deletes a picture """
    try:
        response = table.scan(FilterExpression=Attr('photoID').eq(photoID))
        item = response['Items'][0]
        table.delete_item(
            Key={
                'albumID': item['albumID'],
                'photoID': item['photoID']
            }
        )
        return True
    except Exception as e:
        print(e)
        return False

def delete_album(albumID):
    """ Delete an entire album """
    response = table.scan(FilterExpression=Attr('albumID').eq(albumID))
    for item in response['Items']:
        delete_picture(item['photoID'])

def delete_user(user):
    """ Deletes the user from the database """
    try:
        user_table.delete_item(
            Key={
                'username': user
            }
        )
        response = table.scan(FilterExpression=Attr('creator').eq(user) & Attr('photoID').eq('thumbnail'))
        for item in response['Items']:
            delete_album(item['albumID'])
        return True
    except Exception as e:
        print(e)
        return False

@app.before_request
def authenticate():
    """ Check if the user is logged in before handling request """
    non_auth_endpoints = ['login', 'signup', 'confirm']
    if request.endpoint not in non_auth_endpoints and \
            request.endpoint != 'static' and \
            'logged_in' not in session:
        return redirect('/login')

def send_email(email_addr, subject, body):
    """ Send an email to specified address containing data """
    # Create a new SES resource and specify a region.
    ses = boto3.client('ses',
        region_name=AWS_REGION,
        aws_access_key_id=AWS_ACCESS_KEY,
        aws_secret_access_key=AWS_SECRET_ACCESS_KEY
    )
    # Try to send the email.
    try:
        #Provide the contents of the email.
        response = ses.send_email(
            Destination={
                'ToAddresses': [email_addr],
            },
            Message={
                'Body': {
                    'Text': {
                        'Data': body
                    },
                },
                'Subject': {
                    'Data': subject
                },
            },
            Source='nwitt12@gmail.com'
        )
        # Display an error if something goes wrong.
    except ClientError as e:
        print(e.response['Error']['Message'])
    else:
        print("Email sent! Message ID:"),
        print(response['MessageId'])


"""
"""

"""
    INSERT YOUR NEW ROUTE HERE (IF NEEDED)
"""

@app.route('/login', methods=['GET', 'POST'])
def login():
    """ Login route

    get:
        description: Endpoint to return login page.
        responses: Login page.
    """
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        salt = read_user_attr(username, 'salt')
        correct_password = read_user_attr(username, 'password')
        validated = bool(read_user_attr(username, 'validated'))
        if salt == False or correct_password == False or validated == False:
            return make_response(jsonify({'error': 'that username does not exist'}), 400)
        access = False
        # lookup if correct
        if bcrypt.checkpw(password.encode(), correct_password.encode()):
            ############# Store a session id right here ####################
            session.permanent = True
            session['logged_in'] = username
            return redirect('/')
        else:
            return make_response(jsonify({'error': 'incorrect password'}), 400)
    else:
        return render_template('login.html')



@app.route('/signup', methods=['GET', 'POST'])
def signup():
    """ Signup route

    get:
        description: Endpoint to signup page
        responses: Signup page.
    post:
        description: Creates user and redirects to login on success
        responses: Login on success and Signup on failure.
    """
    if request.method == 'POST':
        password = request.form['password']
        if password == request.form['password1']:
            email = request.form['email']
            username = request.form['username']
            salt = bcrypt.gensalt()
            hashed = bcrypt.hashpw(password.encode(), salt).decode()
            user = {
                'username': request.form['username'],
                'password': hashed,
                'salt': salt.decode(),
                'name': request.form['name'],
                'email': email,
                'validated': False,
            }
            success = create_user(user)
            if success:
                # send confirmation email
                token = serializer.dumps(username, salt=salt) 
                url_id = '..'.join([username, token])
                url = '/'.join([EC2_URL, 'confirm', url_id])
                subject='Photogallery Validation'
                body='Visit this link to activate your account: ' + url
                send_email(email, subject, body)
                return redirect('/login')
        return make_response(jsonify({'error': 'something went wrong'}), 400)
    else:
        return render_template('signup.html')


@app.route('/confirm/<string:ID>', methods=['GET'])
def confirm(ID):
    """ Confirmation route

    get:
        description: Route to validate a user from email
        responses: Login page
    """
    i = ID.find('..')
    username = ID[0:i]
    token = ID[i+2:]
    salt = read_user_attr(username, 'salt')
    if salt == False:
        return make_response(jsonify({'error': 'user does not exist'}), 400)
    username_check = None
    try:
        username_check = serializer.loads(token, salt=salt, max_age=600)
    except Exception as e:
        print(e)
        return make_response(jsonify({'error': 'token error'}), 400)
    if username_check == username:
        write_user_attr(username, 'validated', True)
        print(f'{username} activated')
        return redirect('/login')
    else:
        return make_response(jsonify({'error': 'signature did not match'}), 400)

    return make_response(jsonify({'error': 'something went wrong'}), 400)

@app.route('/cancel-account', methods=['GET'])
def cancel_account():
    """ Delete user account

    get:
        description: Route to delete a user account
        responses: Login page
    """
    username = session['logged_in']
    delete_user(username)
    return redirect('/login')

@app.route('/album/<string:albumID>/photo/<string:photoID>/delete-photo', methods=['GET'])
def delete_photo_route(albumID, photoID):
    """ Delete photo

    get:
        description: Route to delete a photo
        responses: Album detail
    """
    delete_picture(photoID)
    return redirect(f'/album/{albumID}')

@app.route('/album/<string:albumID>/delete-album', methods=['GET'])
def delete_album_route(albumID):
    """ Delete album

    get:
        description: Route to delete an album
        responses: Home
    """
    delete_album(albumID)
    return redirect(f'/')

@app.route('/album/<string:albumID>/photo/<string:photoID>/update-photo', methods=['GET', 'POST'])
def update_photo_route(albumID, photoID):
    """ Update photo

    get:
        description: Route to update a photo
        responses: Photo detail
    """
    if request.method == 'POST':
        createdAtlocalTime = datetime.now().astimezone()
        updatedAtlocalTime = datetime.now().astimezone()

        createdAtUTCTime = createdAtlocalTime.astimezone(pytz.utc)
        updatedAtUTCTime = updatedAtlocalTime.astimezone(pytz.utc)

        write_photo_attr(photoID, 'title', request.form['title'])
        write_photo_attr(photoID, 'description', request.form['description'])
        write_photo_attr(photoID, 'tags', request.form['tags'])
        write_photo_attr(photoID, 'updatedAt', updatedAtUTCTime.strftime("%Y-%m-%d %H:%M:%S"))
        return redirect(f'/album/{albumID}/photo/{photoID}')
    else:
        albumResponse = table.query(KeyConditionExpression=Key('albumID').eq(albumID) & Key('photoID').eq('thumbnail'))
        albumMeta = albumResponse['Items']
        photoResponse = table.query(KeyConditionExpression=Key('albumID').eq(albumID) & Key('photoID').eq(photoID))
        photo=photoResponse['Items'][0]
        return render_template('photoUpdateForm.html', albumID=albumID, albumName=albumMeta[0]['name'], photo=photo)

"""
"""

@app.errorhandler(400)
def bad_request(error):
    """ 400 page route.

    get:
        description: Endpoint to return a bad request 400 page.
        responses: Returns 400 object.
    """
    return make_response(jsonify({'error': 'Bad request'}), 400)



@app.errorhandler(404)
def not_found(error):
    """ 404 page route.

    get:
        description: Endpoint to return a not found 404 page.
        responses: Returns 404 object.
    """
    return make_response(jsonify({'error': 'Not found'}), 404)



@app.route('/', methods=['GET'])
def home_page():
    """ Home page route.

    get:
        description: Endpoint to return home page.
        responses: Returns all the albums.
    """
    response = table.scan(FilterExpression=Attr('photoID').eq("thumbnail"))
    results = response['Items']

    if len(results) > 0:
        for index, value in enumerate(results):
            createdAt = datetime.strptime(str(results[index]['createdAt']), "%Y-%m-%d %H:%M:%S")
            createdAt_UTC = pytz.timezone("UTC").localize(createdAt)
            results[index]['createdAt'] = createdAt_UTC.astimezone(pytz.timezone("US/Eastern")).strftime("%B %d, %Y")

    return render_template('index.html', albums=results)



@app.route('/createAlbum', methods=['GET', 'POST'])
def add_album():
    """ Create new album route.

    get:
        description: Endpoint to return form to create a new album.
        responses: Returns all the fields needed to store new album.

    post:
        description: Endpoint to send new album.
        responses: Returns user to home page.
    """
    if request.method == 'POST':
        uploadedFileURL=''
        file = request.files['imagefile']
        name = request.form['name']
        description = request.form['description']

        if file and allowed_file(file.filename):
            albumID = uuid.uuid4()
            
            filename = file.filename
            filenameWithPath = os.path.join(UPLOAD_FOLDER, filename)
            file.save(filenameWithPath)
            
            uploadedFileURL = s3uploading(str(albumID), filenameWithPath, "thumbnails");

            createdAtlocalTime = datetime.now().astimezone()
            createdAtUTCTime = createdAtlocalTime.astimezone(pytz.utc)

            table.put_item(
                Item={
                    "albumID": str(albumID),
                    "photoID": "thumbnail",
                    "name": name,
                    "description": description,
                    "thumbnailURL": uploadedFileURL,
                    "createdAt": createdAtUTCTime.strftime("%Y-%m-%d %H:%M:%S"),
                    ############# Added Attribute ###############
                    "creator": session['logged_in']
                }
            )

        return redirect('/')
    else:
        return render_template('albumForm.html')



@app.route('/album/<string:albumID>', methods=['GET'])
def view_photos(albumID):
    """ Album page route.

    get:
        description: Endpoint to return an album.
        responses: Returns all the photos of a particular album.
    """
    albumResponse = table.query(KeyConditionExpression=Key('albumID').eq(albumID) & Key('photoID').eq('thumbnail'))
    albumMeta = albumResponse['Items']

    response = table.scan(FilterExpression=Attr('albumID').eq(albumID) & Attr('photoID').ne('thumbnail'))
    items = response['Items']

    return render_template('viewphotos.html', photos=items, albumID=albumID, albumName=albumMeta[0]['name'])



@app.route('/album/<string:albumID>/addPhoto', methods=['GET', 'POST'])
def add_photo(albumID):
    """ Create new photo under album route.

    get:
        description: Endpoint to return form to create a new photo.
        responses: Returns all the fields needed to store a new photo.

    post:
        description: Endpoint to send new photo.
        responses: Returns user to album page.
    """
    if request.method == 'POST':    
        uploadedFileURL=''
        file = request.files['imagefile']
        title = request.form['title']
        description = request.form['description']
        tags = request.form['tags']

        if file and allowed_file(file.filename):
            photoID = uuid.uuid4()
            filename = file.filename
            filenameWithPath = os.path.join(UPLOAD_FOLDER, filename)
            file.save(filenameWithPath)            
            
            uploadedFileURL = s3uploading(filename, filenameWithPath);
            
            ExifData=getExifData(filenameWithPath)
            ExifDataStr = json.dumps(ExifData)

            createdAtlocalTime = datetime.now().astimezone()
            updatedAtlocalTime = datetime.now().astimezone()

            createdAtUTCTime = createdAtlocalTime.astimezone(pytz.utc)
            updatedAtUTCTime = updatedAtlocalTime.astimezone(pytz.utc)

            table.put_item(
                Item={
                    "albumID": str(albumID),
                    "photoID": str(photoID),
                    "title": title,
                    "description": description,
                    "tags": tags,
                    "photoURL": uploadedFileURL,
                    "EXIF": ExifDataStr,
                    "createdAt": createdAtUTCTime.strftime("%Y-%m-%d %H:%M:%S"),
                    "updatedAt": updatedAtUTCTime.strftime("%Y-%m-%d %H:%M:%S"),
                    "creator": session['logged_in'],
                }
            )

        return redirect(f'''/album/{albumID}''')

    else:

        albumResponse = table.query(KeyConditionExpression=Key('albumID').eq(albumID) & Key('photoID').eq('thumbnail'))
        albumMeta = albumResponse['Items']

        return render_template('photoForm.html', albumID=albumID, albumName=albumMeta[0]['name'])



@app.route('/album/<string:albumID>/photo/<string:photoID>', methods=['GET'])
def view_photo(albumID, photoID):
    """ photo page route.

    get:
        description: Endpoint to return a photo.
        responses: Returns a photo from a particular album.
    """ 
    albumResponse = table.query(KeyConditionExpression=Key('albumID').eq(albumID) & Key('photoID').eq('thumbnail'))
    albumMeta = albumResponse['Items']

    response = table.query( KeyConditionExpression=Key('albumID').eq(albumID) & Key('photoID').eq(photoID))
    results = response['Items']

    if len(results) > 0:
        photo={}
        ########### Added AlbumID ##########
        photo['albumID'] = albumID
        ####################################
        photo['photoID'] = results[0]['photoID']
        photo['title'] = results[0]['title']
        photo['description'] = results[0]['description']
        photo['tags'] = results[0]['tags']
        photo['photoURL'] = results[0]['photoURL']
        photo['EXIF']=json.loads(results[0]['EXIF'])

        createdAt = datetime.strptime(str(results[0]['createdAt']), "%Y-%m-%d %H:%M:%S")
        updatedAt = datetime.strptime(str(results[0]['updatedAt']), "%Y-%m-%d %H:%M:%S")

        createdAt_UTC = pytz.timezone("UTC").localize(createdAt)
        updatedAt_UTC = pytz.timezone("UTC").localize(updatedAt)

        photo['createdAt']=createdAt_UTC.astimezone(pytz.timezone("US/Eastern")).strftime("%B %d, %Y at %I:%M:%S %p")
        photo['updatedAt']=updatedAt_UTC.astimezone(pytz.timezone("US/Eastern")).strftime("%B %d, %Y at %I:%M:%S %p")
        
        tags=photo['tags'].split(',')
        exifdata=photo['EXIF']
        
        return render_template('photodetail.html', photo=photo, tags=tags, exifdata=exifdata, albumID=albumID, albumName=albumMeta[0]['name'])
    else:
        return render_template('photodetail.html', photo={}, tags=[], exifdata={}, albumID=albumID, albumName="")



@app.route('/album/search', methods=['GET'])
def search_album_page():
    """ search album page route.

    get:
        description: Endpoint to return all the matching albums.
        responses: Returns all the albums based on a particular query.
    """ 
    query = request.args.get('query', None)    

    response = table.scan(FilterExpression=Attr('name').contains(query) | Attr('description').contains(query))
    results = response['Items']

    items=[]
    for item in results:
        if item['photoID'] == 'thumbnail':
            album={}
            album['albumID'] = item['albumID']
            album['name'] = item['name']
            album['description'] = item['description']
            album['thumbnailURL'] = item['thumbnailURL']
            items.append(album)

    return render_template('searchAlbum.html', albums=items, searchquery=query)



@app.route('/album/<string:albumID>/search', methods=['GET'])
def search_photo_page(albumID):
    """ search photo page route.

    get:
        description: Endpoint to return all the matching photos.
        responses: Returns all the photos from an album based on a particular query.
    """ 
    query = request.args.get('query', None)    

    response = table.scan(FilterExpression=Attr('title').contains(query) | Attr('description').contains(query) | Attr('tags').contains(query) | Attr('EXIF').contains(query))
    results = response['Items']

    items=[]
    for item in results:
        if item['photoID'] != 'thumbnail' and item['albumID'] == albumID:
            photo={}
            photo['photoID'] = item['photoID']
            photo['albumID'] = item['albumID']
            photo['title'] = item['title']
            photo['description'] = item['description']
            photo['photoURL'] = item['photoURL']
            items.append(photo)

    return render_template('searchPhoto.html', photos=items, searchquery=query, albumID=albumID)



if __name__ == '__main__':
    app.run(debug=True, host="0.0.0.0", port=5000)
