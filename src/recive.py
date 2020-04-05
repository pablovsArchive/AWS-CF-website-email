import boto3
import os
import json
import uuid

def recive(event, context):
    """
        This lambda function will recive a AWS SES email recived event.
        It will first collect existing users in the specific domain s3 bucket.
        Then it will check if the email recived is spam, virus or spf.

    """
    s3 = boto3.client('s3')
    domain = os.environ['DOMAIN']

    # Get current user for the specific domain. There is always admin.
    GetCurrentDomainUsers = s3.list_objects(
        Bucket = domain,
        Prefix = 'mail/',
        Delimiter = '/'
    )
    CurrentDomainUsers = []
    for user in GetCurrentDomainUsers.get('CommonPrefixes'):
        CurrentDomainUsers.append(user['Prefix'].split('/')[1])
    
    # Check for spam, virus or spf. If spam it will mark the email as spam.
    # If virus or spf the fucntion will return and the email will not be saved.
    # Else the function will just continue.
    if event['Records'][0]['ses']['receipt']['spamVerdict']['status'] != "PASS":
        spam = True
    else:
        spam = False
    if event['Records'][0]['ses']['receipt']['virusVerdict']['status'] != "PASS":
        return
    if event['Records'][0]['ses']['receipt']['spfVerdict']['status'] != "PASS":
        return

    # Gather recipients, check if they belong to the current domain and the user
    # exists in the current domain. If the user does not exist the email will default
    # to the admin account
    for recipient in event['Records'][0]['ses']['receipt']['recipients']:
        recipientName = recipient.split("@")[0]
        recipientDomain = recipient.split("@")[1]

        if spam:
            folder = "spam"
        else:
            folder = "recived"

        if domain == recipientDomain:
            if recipientName in CurrentDomainUsers:
                s3.put_object(
                    Bucket = domain,
                    Key = 'mail/%s/%s/%s' % (recipientName, folder, str(uuid.uuid4)),
                    Body = json.dumps(event)
                )
            else:
                print("recipient does not exist")
                s3.put_object(
                    Bucket = domain,
                    Key = 'mail/admin/lost/%s/%s' % (folder, str(uuid.uuid4())),
                    Body = json.dumps(event)
                )
        else:
            print("recipient does not correspond to domain")