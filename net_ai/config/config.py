## Program calls
from utilities.logging import *
## Lib calls
import time
import os
import json


path = "assets/config.json"
## Main
def get_pcapqueue():
  try:
    import os.path
    file_exists = os.path.exists(path)
    if file_exists:
      with open(path) as json_file:
        data = json.load(json_file)
        return data['main']['pcapqueue']
    else:
      logp(f"Could not find config.json file!, please make sure it is in the same directory as the script!")
  except:
    logp(f"Config data missing or invalid, check config.json file!")
    exit(0)

def get_debug():
  try:
    import os.path
    file_exists = os.path.exists(path)
    if file_exists:
      with open(path) as json_file:
        data = json.load(json_file)
        return data['main']['debug']
    else:
      logp(f"Could not find config.json file!, please make sure it is in the same directory as the script!")
  except:
    logp(f"Config data missing or invalid, check config.json file!")
    exit(0)

## Live monitor of system
def get_livediscordwebhook():
  try:
    import os.path
    file_exists = os.path.exists(path)
    if file_exists:
      with open(path) as json_file:
        data = json.load(json_file)
        return data['live-monitor']['discordwebhook']
    else:
      logp(f"Could not find config.json file!, please make sure it is in the same directory as the script!")
  except:
    logp(f"Config data missing or invalid, check config.json file!")
    exit(0)

## Staff disocrd webhooks
def get_discordwebhook():
  try:
    import os.path
    file_exists = os.path.exists(path)
    if file_exists:
      with open(path) as json_file:
        data = json.load(json_file)
        return data['staff-discord']['pcapdiscordwebhook']
    else:
      logp(f"Could not find config.json file!, please make sure it is in the same directory as the script!")
  except:
    logp(f"Config data missing or invalid, check config.json file!")
    exit(0)
def get_pcapqueue():
  try:
    import os.path
    file_exists = os.path.exists(path)
    if file_exists:
      with open(path) as json_file:
        data = json.load(json_file)
        return data['staff-discord']['spoiler']
    else:
      logp(f"Could not find config.json file!, please make sure it is in the same directory as the script!")
  except:
    logp(f"Config data missing or invalid, check config.json file!")
    exit(0)
def get_pcapqueue():
  try:
    import os.path
    file_exists = os.path.exists(path)
    if file_exists:
      with open(path) as json_file:
        data = json.load(json_file)
        return data['staff-discord']['ipinfo']
    else:
      logp(f"Could not find config.json file!, please make sure it is in the same directory as the script!")
  except:
    logp(f"Config data missing or invalid, check config.json file!")
    exit(0)
    
## Telegram
def get_telewebhook():
  try:
    import os.path
    file_exists = os.path.exists(path)
    if file_exists:
      with open(path) as json_file:
        data = json.load(json_file)
        return data['staff-telegram']['webhook_url']
    else:
      logp(f"Could not find config.json file!, please make sure it is in the same directory as the script!")
  except:
    logp(f"Config data missing or invalid, check config.json file!")
    exit(0)
def get_telegramchatid():
  try:
    import os.path
    file_exists = os.path.exists(path)
    if file_exists:
      with open(path) as json_file:
        data = json.load(json_file)
        return data['staff-telegram']['telegramchatid']
    else:
      logp(f"Could not find config.json file!, please make sure it is in the same directory as the script!")
  except:
    logp(f"Config data missing or invalid, check config.json file!")
    exit(0)
