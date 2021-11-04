#!flask/bin/python
import sys, os
sys.path.append(os.path.abspath(os.path.join('..', 'utils')))
from env import AWS_ACCESS_KEY, AWS_SECRET_ACCESS_KEY, AWS_REGION, PHOTOGALLERY_S3_BUCKET_NAME, RDS_DB_HOSTNAME, RDS_DB_USERNAME, RDS_DB_PASSWORD, RDS_DB_NAME
from flask import Flask, jsonify, abort, request, make_response, url_for
from flask import render_template, redirect
import time
import exifread
import json
import uuid
import boto3  
import pymysql.cursors
from datetime import datetime
from pytz import timezone

"""
    INSERT NEW LIBRARIES HERE (IF NEEDED)
"""

from env import *
import bcrypt
from itsdangerous import URLSafeTimedSerializer
from botocore.exceptions import ClientError
from flask import session
from datetime import timedelta

"""
"""

app = Flask(__name__, static_url_path="")

"""
    Added Global Configurations
"""
serializer = URLSafeTimedSerializer(URL_KEY)
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

def get_database_connection():
    conn = pymysql.connect(host=RDS_DB_HOSTNAME,
                             user=RDS_DB_USERNAME,
                             password=RDS_DB_PASSWORD,
                             db=RDS_DB_NAME,
                             charset='utf8mb4',
                             cursorclass=pymysql.cursors.DictCursor)
    return conn

def send_email(email, body):
    try:
        ses = boto3.client('ses', aws_access_key_id=AWS_ACCESS_KEY,
                                aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
                                region_name=REGION)
        ses.send_email(
            Source=os.getenv('SES_EMAIL_SOURCE'),
            Destination={'ToAddresses': [email]},
            Message={
                'Subject': {'Data': 'Photo Gallery: Confirm Your Account'},
                'Body': {
                    'Text': {'Data': body}
                }
            }
        )

    except ClientError as e:
        print(e.response['Error']['Message'])

        return False
    else:
        print("Email sent! Message ID:"),
        print(response['MessageId'])

        return True


"""
    INSERT YOUR NEW FUNCTION HERE (IF NEEDED)
"""

def read_user_attr(username, attr):
    """ Get an attribute from a specified user """
    statement = f'''SELECT * FROM photogallerydb.User WHERE userID="{username}";'''
    conn=get_database_connection()
    cursor = conn.cursor ()
    cursor.execute(statement)
    value = cursor.fetchall()[0][attr]
    print(f'User {attr} - {value}')
    conn.close
    return value 

def write_user_attr(username, attr, value):
    """ Write the user attribute to value """
    conn=get_database_connection()
    cursor = conn.cursor ()
    try:
        statement = f'UPDATE photogallerydb.User SET {attr} = "{value}" WHERE userID = "{username}"'
        print(statement)
        cursor.execute(statement)
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        print(e)
        return False

def write_photo_attr(photoID, attr, value):
    """ Set the specified photo attribute to value """
    conn=get_database_connection()
    cursor = conn.cursor ()
    try:
        statement = f'UPDATE photogallerydb.Photo SET {attr} = "{value}" WHERE photoID = "{photoID}"'
        print(statement)
        cursor.execute(statement)
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        print(e)
        return False
    pass
 
def create_user(user):
    """ Checks database for existing username and/or email.  If
        none exists, create a new user in the database
    """
    conn=get_database_connection()
    cursor = conn.cursor ()
    try:
        cursor.execute('INSERT INTO photogallerydb.User (userID, email, firstName, lastName, password, salt, validated) VALUES ("{}", "{}", "{}", "{}", "{}", "{}", "{}");'.format(*list(user.values())))
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        print(e)
        return False

def delete_picture(photoID):
    """ Deletes a picture """
    conn=get_database_connection()
    cursor = conn.cursor ()
    try:
        statement = f'''DELETE FROM photogallerydb.Photo WHERE photoID="{photoID}";'''
        cursor.execute(statement)
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        print(e)
        return False

def delete_album(albumID):
    """ Delete an entire album """
    conn=get_database_connection()
    cursor = conn.cursor ()
    try:
        statement = f'''DELETE FROM photogallerydb.Album WHERE albumID="{albumID}";'''
        cursor.execute(statement)
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        print(e)
        return False

def delete_user(user):
    """ Deletes the user from the database """
    conn=get_database_connection()
    cursor = conn.cursor ()
    try:
        statement = f'''DELETE FROM photogallerydb.User WHERE userID="{user}";'''
        cursor.execute(statement)
        conn.commit()
        conn.close()
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
        validated = read_user_attr(username, 'validated') == 'True'
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
            name = request.form['name'].split(' ')
            assert(len(name) == 2)
            firstName = name[0]
            lastName = name[1]
            salt = bcrypt.gensalt()
            hashed = bcrypt.hashpw(password.encode(), salt).decode()
            user = {
                'username': request.form['username'],
                'email': email,
                'firstName': firstName,
                'lastName': lastName,
                'password': hashed,
                'salt': salt.decode(),
                'validated': 'False',
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
        write_photo_attr(photoID, 'title', request.form['title'])
        write_photo_attr(photoID, 'description', request.form['description'])
        write_photo_attr(photoID, 'tags', request.form['tags'])
        return redirect(f'/album/{albumID}/photo/{photoID}')
    else:
        conn=get_database_connection()
        cursor = conn.cursor ()
        # Get title
        statement = f'''SELECT * FROM photogallerydb.Album WHERE albumID="{albumID}";'''
        cursor.execute(statement)
        albumMeta = cursor.fetchall()
        statement = f'''SELECT * FROM photogallerydb.Photo WHERE photoID="{photoID}";'''
        cursor.execute(statement)
        photo = cursor.fetchall()[0]
        conn.close()

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
    conn=get_database_connection()
    cursor = conn.cursor ()
    cursor.execute("SELECT * FROM photogallerydb.Album;")
    results = cursor.fetchall()
    conn.close()
    
    items=[]
    for item in results:
        album={}
        album['albumID'] = item['albumID']
        album['name'] = item['name']
        album['description'] = item['description']
        album['thumbnailURL'] = item['thumbnailURL']

        createdAt = datetime.strptime(str(item['createdAt']), "%Y-%m-%d %H:%M:%S")
        createdAt_UTC = timezone("UTC").localize(createdAt)
        album['createdAt']=createdAt_UTC.astimezone(timezone("US/Eastern")).strftime("%B %d, %Y")

        items.append(album)

    return render_template('index.html', albums=items)



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

            conn=get_database_connection()
            cursor = conn.cursor ()
            ########### ADD Creator ##################
            statement = f'''INSERT INTO photogallerydb.Album (albumID, name, description, thumbnailURL, Creator) VALUES ("{albumID}", "{name}", "{description}", "{uploadedFileURL}", "{session['logged_in']}");'''
            ##########################################
            
            result = cursor.execute(statement)
            conn.commit()
            conn.close()

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
    conn=get_database_connection()
    cursor = conn.cursor ()
    # Get title
    statement = f'''SELECT * FROM photogallerydb.Album WHERE albumID="{albumID}";'''
    cursor.execute(statement)
    albumMeta = cursor.fetchall()
    
    # Photos
    statement = f'''SELECT photoID, albumID, title, description, photoURL FROM photogallerydb.Photo WHERE albumID="{albumID}";'''
    cursor.execute(statement)
    results = cursor.fetchall()
    conn.close() 
    
    items=[]
    for item in results:
        photos={}
        photos['photoID'] = item['photoID']
        photos['albumID'] = item['albumID']
        photos['title'] = item['title']
        photos['description'] = item['description']
        photos['photoURL'] = item['photoURL']
        items.append(photos)

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

            conn=get_database_connection()
            cursor = conn.cursor ()
            ExifDataStr = json.dumps(ExifData)
            statement = f'''INSERT INTO photogallerydb.Photo (PhotoID, albumID, title, description, tags, photoURL, EXIF) VALUES ("{photoID}", "{albumID}", "{title}", "{description}", "{tags}", "{uploadedFileURL}", %s);'''
            
            result = cursor.execute(statement, (ExifDataStr,))
            conn.commit()
            conn.close()

        return redirect(f'''/album/{albumID}''')
    else:
        conn=get_database_connection()
        cursor = conn.cursor ()
        # Get title
        statement = f'''SELECT * FROM photogallerydb.Album WHERE albumID="{albumID}";'''
        cursor.execute(statement)
        albumMeta = cursor.fetchall()
        conn.close()

        return render_template('photoForm.html', albumID=albumID, albumName=albumMeta[0]['name'])



@app.route('/album/<string:albumID>/photo/<string:photoID>', methods=['GET'])
def view_photo(albumID, photoID):  
    """ photo page route.

    get:
        description: Endpoint to return a photo.
        responses: Returns a photo from a particular album.
    """ 
    conn=get_database_connection()
    cursor = conn.cursor ()

    # Get title
    statement = f'''SELECT * FROM photogallerydb.Album WHERE albumID="{albumID}";'''
    cursor.execute(statement)
    albumMeta = cursor.fetchall()

    statement = f'''SELECT * FROM photogallerydb.Photo WHERE albumID="{albumID}" and photoID="{photoID}";'''
    cursor.execute(statement)
    results = cursor.fetchall()
    conn.close()

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

        createdAt_UTC = timezone("UTC").localize(createdAt)
        updatedAt_UTC = timezone("UTC").localize(updatedAt)

        photo['createdAt']=createdAt_UTC.astimezone(timezone("US/Eastern")).strftime("%B %d, %Y at %-I:%M:%S %p")
        photo['updatedAt']=updatedAt_UTC.astimezone(timezone("US/Eastern")).strftime("%B %d, %Y at %-I:%M:%S %p")
        
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

    conn=get_database_connection()
    cursor = conn.cursor ()
    statement = f'''SELECT * FROM photogallerydb.Album WHERE name LIKE '%{query}%' UNION SELECT * FROM photogallerydb.Album WHERE description LIKE '%{query}%';'''
    cursor.execute(statement)

    results = cursor.fetchall()
    conn.close()

    items=[]
    for item in results:
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

    conn=get_database_connection()
    cursor = conn.cursor ()
    statement = f'''SELECT * FROM photogallerydb.Photo WHERE title LIKE '%{query}%' AND albumID="{albumID}" UNION SELECT * FROM photogallerydb.Photo WHERE description LIKE '%{query}%' AND albumID="{albumID}" UNION SELECT * FROM photogallerydb.Photo WHERE tags LIKE '%{query}%' AND albumID="{albumID}" UNION SELECT * FROM photogallerydb.Photo WHERE EXIF LIKE '%{query}%' AND albumID="{albumID}";'''
    cursor.execute(statement)

    results = cursor.fetchall()
    conn.close()

    items=[]
    for item in results:
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
