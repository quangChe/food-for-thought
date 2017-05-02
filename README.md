# Food for Thought

A multi-user blog made using python, webapp2, jinja2 and Google Cloud's App Engine to power the server and Google's Datastore for the database.

## Tools implemented:


* OS: To configure template directories for Jinja2
* Re: For validating signup/login values (usernames, passwords, email)
* Random: Used with string to generate random letters for the salt that is used to hash the password
* String: Used with random in order to make the string for the salt in the password hash
* Time: To set a delay time before redirecting to a page in order for it to reflect changes made to the database
* Hashlib: Used to hash the password of users
* Hmac: Used in conjunction with a secret in order to set cookie data for logged-in user's info
* Webapp2: Provides the route handling the blog
* Jinja2: Renders and manipulate templates for each route on the site blog
* Db from google.appengine.ext: Used to access Google Datastore functions for defining, querying and manipulating database models.

## How to run:

**Note:** Do not make any changes to the directories, app.yaml and index.yaml or errors may occur.

### Initial Setup:
1. Install python 2.7 (required for standard gcloud)
2. Configure the Google Cloud App Engine Environment by installing the Google Cloud SDK. More details on that [here](https://cloud.google.com/appengine/docs/standard/python/quickstart).


### Running on a local server:
1. With the Google Cloud SDK set up, navigate to the root directory of the app (Multi-User Blog)
2. Run a local server in the terminal using command: '$ dev_appserver.py .'
3. If no changes have been made the the repository, the app will be able to be viewed on 'http://localhost:8080/'


### Deploying to Google Cloud App Engine:

1. You must first have an account set up to use Google Cloud App Engine.
2. After logging in, access your Google Cloud Platform Console and create a project (note the name of this project).
3. With the Google Cloud SDK set up, deploy the app onto Google Cloud App Engine in the terminal using command: '$ gcloud app deploy'
4. Configure the deploy by following the prompts that follow on the terminal.
5. In order to prevent Datastore index errors, run: '$ gcloud add index.yaml'
6. After the deploy is finished, access the app using the URL created or running: '% gcloud app browse'


###### The app can be accessed [here](https://food-for-thought-qc.appspot.com/).
