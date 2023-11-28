# Jamf LAPS via Dialog
Retrieve LAPS information in Jamf Pro via swiftDialog

This script will provide a user interface for retrieving the LAPS password associated with a Jamf Pro managed computer. This script can be ran locally or made availabe in Self Service. 

# Screenshots
Jamf LAPS via Dialog:

<img width="932" alt="Screenshot 2023-11-28 at 3 12 55 PM" src="https://github.com/robjschroeder/Jamf-LAPS-via-Dialog/assets/23343243/28697797-ef85-4947-a2d3-422ed768ba2f">
<br>If no credentials or Jamf Pro URL are provided, the dialog screen will require input of these items. 

The dialog screen will ask only for items that are required. 
<img width="932" alt="Screenshot 2023-11-28 at 3 16 11 PM" src="https://github.com/robjschroeder/Jamf-LAPS-via-Dialog/assets/23343243/46a1ba82-27fd-4214-b72b-4326f91ecd34">

<br>After inputing the required information and clicking 'Continue', the script will use the Jamf Pro API to gather some additional information on the computer. You will be asked which account that you are looking to get the password for.
<img width="1012" alt="Screenshot 2023-11-28 at 3 18 33 PM" src="https://github.com/robjschroeder/Jamf-LAPS-via-Dialog/assets/23343243/627153ff-8f4e-4e59-b4fe-79ddbb431b6f">

<br>Finally you will be presented with the selected user's password. 
<img width="932" alt="Screenshot 2023-11-28 at 3 18 40 PM" src="https://github.com/robjschroeder/Jamf-LAPS-via-Dialog/assets/23343243/2cc137e4-40cb-43a2-81ec-51ffa6dc123f">


# Why Build This
After reviewing Mark Buffington and Rob Potvin's JNUC 2023 presentation on Jamf Pro LAPS, and having recent issues that required administrator credentials to resolve (all users in our organization do not have local administrative rights), I noticed that I needed a way to pull administrator passwords easily. Also, I love all things swiftDialog so why not have a dialog available to get this informaiton. This tool can then be made available to all support staff that may need to get administrator credentials for hands-on work. Security is then increased by auto-rotating the password after a certain amount of time after it has been viewed. 

# Usage
