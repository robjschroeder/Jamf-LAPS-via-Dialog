#!/bin/bash
# shellcheck disable=SC2317,SC2089,SC2001,SC2140,SC2207,SC2005

####################################################################################################
#
# Jamf LAPS via Dialog
#
####################################################################################################
#
# HISTORY
#
#   Version 1.0.0, 11.27.2023, Robert Schroeder (@robjschroeder)
#   - If using a Jamf Pro API Client ID and Secret, the role used should have the following minimum permissions:
#   -- "View Local Admin Password"
#   -- "Read Computers"
#   
#
####################################################################################################

####################################################################################################
#
# Global Variables
#
####################################################################################################

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Script Version and Jamf Pro API Variables
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

scriptVersion="1.0.0"
scriptFunctionalName="Jamf LAPS via Dialog"
export PATH=/usr/bin:/bin:/usr/sbin:/sbin

scriptLog="${4:-"/var/log/com.company.log"}"                  # Parameter 4: Script Log Location [ /var/log/com.compay.log ] (ie., Your organization's default location for client-side logs)
jamfProURL="${5:-""}"                                           # Parameter 5: Jamf Pro URL [ https://server.jamfcloud.com ]

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
###  Setting Jamf API Client and Secret will overwrite any prompt for Jamf Pro API Credentials  ###
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
jamfProAPIClient="${6:-""}"                                     # Parameter 6: Jamf Pro API Client ID
jamfProAPISecret="${7:-""}"                                     # Parameter 7: Jamf Pro API Client Secret
useOverlayIcon="${8:-"true"}"                                   # Parameter 8: Use Overlay Icon [ true (default) | false ]


# Dialog Icon Icons
brandingIconLight="SF=lock.icloud"
brandingIconDark="SF=lock.icloud.fill"

####################################################################################################
#
# Functions
#
####################################################################################################

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Pre-flight Check: Client-side Logging
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

if [[ ! -f "${scriptLog}" ]]; then
    touch "${scriptLog}"
fi


# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Pre-flight Check: Client-side Script Logging Function
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

function updateScriptLog() {
    echo "${scriptFunctionalName}: $( date +%Y-%m-%d\ %H:%M:%S ) - ${1}" | tee -a "${scriptLog}"
}

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Pre-flight Check: Current Logged-in User Function
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

function currentLoggedInUser() {
    loggedInUser=$( echo "show State:/Users/ConsoleUser" | scutil | awk '/Name :/ { print $3 }' )
    updateScriptLog "PRE-FLIGHT CHECK: Current Logged-in User: ${loggedInUser}"
}

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Pre-flight Check: Logging Preamble
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

updateScriptLog "\n\n###\n# ${scriptFunctionalName} (${scriptVersion}) ### https://techitout.xyz/ ###"
updateScriptLog "PRE-FLIGHT CHECK: Initiating …"

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Pre-flight Check: Confirm Dock is running / user is at Desktop
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

until pgrep -q -x "Finder" && pgrep -q -x "Dock"; do
    updateScriptLog "PRE-FLIGHT CHECK: Finder & Dock are NOT running; pausing for 1 second"
    sleep 1
done

updateScriptLog "PRE-FLIGHT CHECK: Finder & Dock are running; proceeding …"

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Pre-flight Check: Validate Logged-in System Accounts
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

updateScriptLog "PRE-FLIGHT CHECK: Check for Logged-in System Accounts …"
currentLoggedInUser

counter="1"

until { [[ "${loggedInUser}" != "_mbsetupuser" ]] || [[ "${counter}" -gt "180" ]]; } && { [[ "${loggedInUser}" != "loginwindow" ]] || [[ "${counter}" -gt "30" ]]; } ; do

    updateScriptLog "PRE-FLIGHT CHECK: Logged-in User Counter: ${counter}"
    currentLoggedInUser
    sleep 2
    ((counter++))

done

loggedInUserFullname=$( id -F "${loggedInUser}" )
loggedInUserFirstname=$( echo "$loggedInUserFullname" | sed -E 's/^.*, // ; s/([^ ]*).*/\1/' | sed 's/\(.\{25\}\).*/\1…/' | awk '{print ( $0 == toupper($0) ? toupper(substr($0,1,1))substr(tolower($0),2) : toupper(substr($0,1,1))substr($0,2) )}' )
loggedInUserID=$( id -u "${loggedInUser}" )
updateScriptLog "PRE-FLIGHT CHECK: Current Logged-in User First Name: ${loggedInUserFirstname}"
updateScriptLog "PRE-FLIGHT CHECK: Current Logged-in User ID: ${loggedInUserID}"

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Pre-flight Check: Validate / install swiftDialog (Thanks big bunches, @acodega!)
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

function dialogInstall() {

    # Get the URL of the latest PKG From the Dialog GitHub repo
    dialogURL=$(curl -L --silent --fail "https://api.github.com/repos/swiftDialog/swiftDialog/releases/latest" | awk -F '"' "/browser_download_url/ && /pkg\"/ { print \$4; exit }")

    # Expected Team ID of the downloaded PKG
    expectedDialogTeamID="PWA5E9TQ59"

    updateScriptLog "PRE-FLIGHT CHECK: Installing swiftDialog..."

    # Create temporary working directory
    workDirectory=$( /usr/bin/basename "$0" )
    tempDirectory=$( /usr/bin/mktemp -d "/private/tmp/$workDirectory.XXXXXX" )

    # Download the installer package
    /usr/bin/curl --location --silent "$dialogURL" -o "$tempDirectory/Dialog.pkg"

    # Verify the download
    teamID=$(/usr/sbin/spctl -a -vv -t install "$tempDirectory/Dialog.pkg" 2>&1 | awk '/origin=/ {print $NF }' | tr -d '()')

    # Install the package if Team ID validates
    if [[ "$expectedDialogTeamID" == "$teamID" ]]; then

        /usr/sbin/installer -pkg "$tempDirectory/Dialog.pkg" -target /
        sleep 2
        dialogVersion=$( /usr/local/bin/dialog --version )
        updateScriptLog "PRE-FLIGHT CHECK: swiftDialog version ${dialogVersion} installed; proceeding..."

    else

        # Display a so-called "simple" dialog if Team ID fails to validate
        osascript -e 'display dialog "Please advise your Support Representative of the following error:\r\r• Dialog Team ID verification failed\r\r" with title "Setup Your Mac: Error" buttons {"Close"} with icon caution'
        completionActionOption="Quit"
        exitCode="1"
        quitScript

    fi

    # Remove the temporary working directory when done
    /bin/rm -Rf "$tempDirectory"

}



function dialogCheck() {

    # Output Line Number in `verbose` Debug Mode
    if [[ "${debugMode}" == "verbose" ]]; then updateScriptLog "PRE-FLIGHT CHECK: # # # SETUP YOUR MAC VERBOSE DEBUG MODE: Line No. ${LINENO} # # #" ; fi

    # Check for Dialog and install if not found
    if [ ! -e "/Library/Application Support/Dialog/Dialog.app" ]; then

        updateScriptLog "PRE-FLIGHT CHECK: swiftDialog not found. Installing..."
        dialogInstall

    else

        dialogVersion=$(/usr/local/bin/dialog --version)
        if [[ "${dialogVersion}" < "${swiftDialogMinimumRequiredVersion}" ]]; then
            
            updateScriptLog "PRE-FLIGHT CHECK: swiftDialog version ${dialogVersion} found but swiftDialog ${swiftDialogMinimumRequiredVersion} or newer is required; updating..."
            dialogInstall
            
        else

        updateScriptLog "PRE-FLIGHT CHECK: swiftDialog version ${dialogVersion} found; proceeding..."

        fi
    
    fi

}

dialogCheck

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Pre-flight Check: Complete
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

updateScriptLog "PRE-FLIGHT CHECK: Complete"

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Parse JSON via osascript and JavaScript
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

function get_json_value() {
    # set -x
    JSON="$1" osascript -l 'JavaScript' \
        -e 'const env = $.NSProcessInfo.processInfo.environment.objectForKey("JSON").js' \
        -e "JSON.parse(env).$2"
    # set +x
}

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Parse JSON via osascript and JavaScript for the start prompt dialog (thanks, @bartreardon!)
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

function get_json_value_startPromptDialog() {
    # set -x
    for var in "${@:2}"; do jsonkey="${jsonkey}['${var}']"; done
    JSON="$1" osascript -l 'JavaScript' \
        -e 'const env = $.NSProcessInfo.processInfo.environment.objectForKey("JSON").js' \
        -e "JSON.parse(env)$jsonkey"
    # set +x
}

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Kill a specified process (thanks, @grahampugh!)
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

function killProcess() {
    process="$1"
    if process_pid=$( pgrep -a "${process}" 2>/dev/null ) ; then
        echo "Attempting to terminate the '$process' process …"
        echo "(Termination message indicates success.)"
        kill "$process_pid" 2> /dev/null
        if pgrep -a "$process" >/dev/null ; then
            echo "ERROR: '$process' could not be terminated."
        fi
    else
        echo "The '$process' process isn't running."
    fi
}

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Quit Script
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

function quitScript() {
    # Set Exit Code
    exitCode="$1"

    if [[ $exitCode = "0" ]]; then
        exitReason="Successfully processed"
    elif [[ $exitCode = "1" ]]; then
        exitReason="User clicked 'Quit'"
    else
        exitReason="Something else happened ..."
    fi

    echo "$exitReason"

    # Clean up temp dialog files
    if [[ -e ${startPromptJSONFile} ]]; then
        updateScriptLog "QUIT: Removing ${startPromptJSONFile} ..."
        rm "${startPromptJSONFile}"
    fi

    if [[ -e ${startPromptCommandFile} ]]; then
        updateScriptLog "QUIT: Removing ${startPromptCommandFile} ..."
        rm "${startPromptCommandFile}"
    fi

    if [[ -e /var/tmp/dialog.log ]]; then
        updateScriptLog "QUIT: Removing dialog.log ..."
        rm /var/tmp/dialog.log
    fi

    if [[ -e ${LAPSPromptCommandFile} ]]; then
        updateScriptLog "QUIT: Removing ${LAPSPromptCommandFile} ..."
        rm "${LAPSPromptCommandFile}"
    fi

    if [[ -e ${LAPSPromptJSONFile} ]]; then
        updateScriptLog "QUIT: Removing ${LAPSPromptJSONFile} ..."
        rm "${LAPSPromptJSONFile}"
    fi

     if [[ -e ${resultsJSONFile} ]]; then
        updateScriptLog "QUIT: Removing ${resultsJSONFile} ..."
        rm "${resultsJSONFile}"
    fi
    
    if [ -n "$authorizationError" ]; then
        updateScriptLog "Authorization Error: ${authorizationError}"
    fi

     if [[ -e ${resultsCommandFile} ]]; then
        updateScriptLog "QUIT: Removing ${resultsCommandFile} ..."
        rm "${resultsCommandFile}"
    fi

    if [[ -e ${overlayicon} ]]; then
        updateScriptLog "QUIT: Removing ${overlayicon} ..."
        rm "${overlayicon}"
    fi


    invalidateToken

    # Kill any Dialog Process
    killProcess "Dialog"

    updateScriptLog "EXIT CODE: $exitCode"
    
    exit "$exitCode"

}

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Jamf Pro API Authentication Functions
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

### Get a bearer token ###

function getBearerToken(){
    
    if [[ -n "${jamfProAPIClient}" ]]; then
        updateScriptLog "Obtaining authentication token using API Client and Secret"
        curl_response=$(curl --silent --location --request POST "${jamfProURL}/api/oauth/token" --header "Content-Type: application/x-www-form-urlencoded" --data-urlencode "client_id=${jamfProAPIClient}" --data-urlencode "grant_type=client_credentials" --data-urlencode "client_secret=${jamfProAPISecret}")
        else # Legacy ${auth_jamf_account} authentication.
        updateScriptLog "Obtaining authentication token with basic credentials"
        curl_response=$(curl --silent --location --request POST "${jamfProURL}/api/v1/auth/token" --user "${jamfProAPIUsername}:${jamfProAPIPassword}")
    fi

    updateScriptLog "Extracting authentication token..."
    if [[ $(echo "${curl_response}" | grep -c 'token') -gt 0 ]]; then
        if [[ -n "${jamfProAPIClient}" ]]; then
            bearerToken=$(echo "${curl_response}" | plutil -extract access_token raw -)
            updateScriptLog "Authentication token received"
        else # Legacy ${auth_jamf_account} authentication.
            bearerToken=$(echo "${curl_response}" | plutil -extract token raw -)
            updateScriptLog "Authentication token received"
        fi
    else # There was no access token.
        if [[ -n "${jamfProAPIClient}" ]]; then
            updateScriptLog "Auth Error: Response from Jamf Pro API access token request did not contain a token. Verify the ClientID and ClientSecret values."; authorizationError="TRUE"
            exitCode="3"
            quitScript $exitCode
        else # Legacy ${auth_jamf_account} authentication.
            updateScriptLog "Auth Error: Response from Jamf Pro API access token request did not contain a token. Verify the jamfProAPIUsername and jamfProAPIPassword values."; authorizationError="TRUE"
            exitCode="3"
            quitScript $exitCode
        fi
        authorizationError="TRUE"
        exitCode="3"
        quitScript "$exitCode"
    fi
}
### Check Token Expiration ###

function checkTokenExpiration() {
    nowEpochUTC=$(date -j -f "%Y-%m-%dT%T" "$(date -u +"%Y-%m-%dT%T")" +"%s")
    if [[ tokenExpirationEpoch -gt nowEpochUTC ]]
    then
        updateScriptLog "Token valid until the following epoch time: " "$tokenExpirationEpoch"
    else
        updateScriptLog "No valid token available, getting new token"
        getBearerToken
    fi
}

### Invalidate the Token ###
function invalidateToken() {
	responseCode=$(curl -w "%{http_code}" -H "Authorization: Bearer ${bearerToken}" "$jamfProURL"/api/v1/auth/invalidate-token -X POST -s -o /dev/null)
	if [[ ${responseCode} == 204 ]]
	then
		updateScriptLog "Token successfully invalidated"
		bearerToken=""
		tokenExpirationEpoch="0"
	elif [[ ${responseCode} == 401 ]]
	then
		updateScriptLog "Token already invalid"
	else
		updateScriptLog "An unknown error occurred invalidating the token"
	fi
}

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Branding Functions
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

function branding(){
    # Icon set to either light or dark, based on user's Apperance setting (thanks, @mm2270!)
    appleInterfaceStyle=$( /usr/bin/defaults read /Users/"${loggedInUser}"/Library/Preferences/.GlobalPreferences.plist AppleInterfaceStyle 2>&1 )
    if [[ "${appleInterfaceStyle}" == "Dark" ]]; then
        if [[ -n "$brandingIconDark" ]]; then startIcon="$brandingIconDark";
        else startIcon="https://cdn-icons-png.flaticon.com/512/740/740878.png"; fi
    else
        if [[ -n "$brandingIconLight" ]]; then startIcon="$brandingIconLight";
        else startIcon="https://cdn-icons-png.flaticon.com/512/979/979585.png"; fi
    fi

    if [[ "$useOverlayIcon" == "true" ]]; then
        # Create `overlayicon` from Self Service's custom icon (thanks, @meschwartz!)
        xxd -p -s 260 "$(defaults read /Library/Preferences/com.jamfsoftware.jamf self_service_app_path)"/Icon$'\r'/..namedfork/rsrc | xxd -r -p > /var/tmp/overlayicon.icns
        overlayicon="/var/tmp/overlayicon.icns"
    fi
}

# Call branding function
branding

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Dialog path and Command Files
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

dialogBinary="/usr/local/bin/dialog"
startPromptJSONFile=$( mktemp -u /var/tmp/startPromptJSONFile.XXX )
startPromptCommandFile=$( mktemp -u /var/tmp/dialogCommandFilestartPrompt.XXX )
LAPSPromptJSONFile=$( mktemp -u /var/tmp/LAPSPromptJSONFile.XXX )
LAPSPromptCommandFile=$( mktemp -u /var/tmp/dialogCommandFileLAPSPrompt.XXX )
resultsJSONFile=$( mktemp -u /var/tmp/resultsJSONFile.XXX )
resultsCommandFile=$( mktemp -u /var/tmp/dialogCommandFileResults.XXX )

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Start Prompt
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

if [ -z "$jamfProURL" ]; then
    updateScriptLog "Jamf Pro URL not defined, adding to dialog"
    jamfProURLJSON='{ "title" : "Jamf Pro URL","required" : true,"prompt" : "https://server.jamfcloud.com" },'
else
    updateScriptLog "Jamf Pro URL was defined as: ${jamfProURL}, skipping prompt..."
fi

if [ -z "$jamfProAPIClient" ] || [ -z "$jamfProAPISecret" ]; then
    updateScriptLog "Adding Jamf Pro API Credential prompt to dialog"
    jamfProAPICredentialsJSON='{ "title" : "Jamf Pro API Username","required" : true },{ "title" : "Jamf Pro API Password","required" : true,"secure" : true },'
else
    updateScriptLog "Jamf Pro API Client and Secret defined, skipping Jamf Pro API Credential prompt"
fi

computerPromptJSON='{ "title" : "Computer Serial or JSS ID","required" : true },'
textfieldJSON="${jamfProURLJSON}${jamfProAPICredentialsJSON}${computerPromptJSON}"
textfieldJSON=$( echo "${textfieldJSON}" | sed 's/,$//' )

startPromptJSON='
{
    "commandfile" : "'"${startPromptCommandFile}"'",
    "title" : "Jamf LAPS via Dialog",
    "infobox" : "This tool is designed to help easy retreival of the LAPS password associated with a Jamf Pro managed computer",
    "icon" : "'"${startIcon}"'",
    "overlayicon" : "'"${overlayicon}"'",
    "iconsize" : "198.0",
    "button1text" : "Continue",
    "button2text" : "Quit",
    "ontop" : "true",
    "position" : "center",
    "moveable" : true,
    "titlefont" : "shadow=true, size=36, colour=#FFFDF4",
    "message" : "\n\n '${loggedInUserFirstname}', enter the required information below:",
    "messagefont" : "size=14",
    "textfield" : [
        '${textfieldJSON}'
    ],
}
'

echo "$startPromptJSON" > "$startPromptJSONFile"

# Display Welcome dialog
updateScriptLog "Displaying API credential prompt to user"
startPromptResults=$( eval "${dialogBinary} --jsonfile ${startPromptJSONFile} --json" )

if [[ -z "${startPromptResults}" ]]; then
    startPromptReturnCode="2"
else
    startPromptReturnCode="0"
fi

case "${startPromptReturnCode}" in

    0) # Process exit code 0 scenario here
        # Set API Crednetial variables
        if [ -z "$jamfProURL" ]; then
            jamfProURL=$(get_json_value_startPromptDialog "$startPromptResults" "Jamf Pro URL")
        fi
        jamfProAPIUsername=$(get_json_value_startPromptDialog "$startPromptResults" "Jamf Pro API Username")
        jamfProAPIPassword=$(get_json_value_startPromptDialog "$startPromptResults" "Jamf Pro API Password")
        serialOrID=$(get_json_value_startPromptDialog "$startPromptResults" "Computer Serial or JSS ID")
        ;;
    2) # Process exit code 2 scenario here
        quitScript "1"
        ;;
    *) # Process catch-all scenario here
        quitScript "2"
        ;;
esac

# Attempt to get a bearer token for API Authentication
checkTokenExpiration

#serialOrID="GQCXQF0YCF"

numberValidation='^[0-9]*$'
if ! [[ "$serialOrID" =~ $numberValidation ]] ; then
    echo "Need to find the ID"
    # Determine the computer's Jamf Pro Computer ID via the computer's Serial Number, "${1}"
    jssID=$( /usr/bin/curl -H "Authorization: Bearer ${bearerToken}" -s "${jamfProURL}"/JSSResource/computers/serialnumber/"${serialOrID}"/subset/general | xpath -e "/computer/general/id/text()" )
else
    jssID="${serialOrID}"
fi

# Get computer information via API
generalComputerInfo=$( /usr/bin/curl -H "Authorization: Bearer ${bearerToken}" -H "Accept: text/xml" -sfk "${jamfProURL}"/JSSResource/computers/id/"${jssID}/subset/General" -X GET )

# Parse individual details
computerName=$( echo "${generalComputerInfo}" | xpath -q -e "/computer/general/name/text()" )
computerSerialNumber=$( echo "${generalComputerInfo}" | xpath -q -e "/computer/general/serial_number/text()" ) 
computerIpAddress=$( echo "${generalComputerInfo}" | xpath -q -e "/computer/general/ip_address/text()" ) 
computerIpAddressLastReported=$( echo "${generalComputerInfo}" | xpath -q -e "/computer/general/last_reported_ip/text()" )
computerInventoryGeneral=$( /usr/bin/curl -H "Authorization: Bearer ${bearerToken}" -s "${jamfProURL}/api/v1/computers-inventory?section=GENERAL&filter=id==${jssID}" -H "accept: application/json" -X GET )
managementID=$(get_json_value "$computerInventoryGeneral" 'results[0].general.managementId' )

updateScriptLog "• Name: $computerName"
updateScriptLog "• Serial Number: $computerSerialNumber"
updateScriptLog "• IP Address: $computerIpAddress"
updateScriptLog "• IP Address (LR): $computerIpAddressLastReported"
updateScriptLog "• Server: ${jamfProURL}"
updateScriptLog "• Computer ID: ${jssID}"

# Get the LAPS accounts
accountInfo=$( curl -X 'GET' \
    --silent \
  "$jamfProURL"/api/v2/local-admin-password/"$managementID"/accounts \
  -H 'accept: application/json' \
  -H "Authorization: Bearer $bearerToken"
)

# Math for populating a list of LAPS accounts to present in dialog
totalCount=$(get_json_value "$accountInfo" 'totalCount')
startingElement="0"

until [ $startingElement = "$totalCount" ]; do
    lapsUsernames+=($(echo "$(get_json_value "$accountInfo" 'results['"'$startingElement'"'].username')"))
    ((startingElement++))
done

for username in "${lapsUsernames[@]}"; do
    updateScriptLog "LAPS user found: $username"
done

# Additional formatting
sortedUniquelapsUsernames=($(echo "${lapsUsernames[@]}" | tr ' ' '\n' | sort -u | tr '\n' ' '))
lapsUsersString=$( echo "${sortedUniquelapsUsernames[@]}" | sed 's/.*/"&"/' | sed 's/\ /",\ "/g' )

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# LAPS Prompt
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

LAPSPromptJSON='
{
    "commandfile" : "'"${LAPSPromptCommandFile}"'",
    "title" : "Jamf LAPS via Dialog",
    "icon" : "'"${startIcon}"'",
    "overlayicon" : "'"${overlayicon}"'",
    "iconsize" : "198.0",
    "button1text" : "Continue",
    "button2text" : "Quit",
    "selectitems": [
        {
            "title" : "LAPS User",
            "values" : [
                '${lapsUsersString}'
            ]
        },
    ],
    "ontop" : "true",
    "position" : "center",
    "moveable" : true,
    "height" : "700",
    "width" : "900",
    "titlefont" : "shadow=true, size=36, colour=#FFFDF4",
    "message" : "\n\n ### **Computer Name:** ###  \n '${computerName}'  \n\n ### **Computer Serial:** ###  \n '${computerSerialNumber}'  \n\n ### **Computer IP Address:** ###  \n '${computerIpAddress}'  \n\n ### **Local IP Address** ###  \n '${computerIpAddressLastReported}'  \n\n ### **JSS ID:** ###  \n '${jssID}'  \n\n ### **Management ID:** ###  \n '${managementID}'  \n\n Select the account you want to retrieve a password for from the dropdown below:",
    "messagefont" : "size=14",
}
'

echo "$LAPSPromptJSON" > "$LAPSPromptJSONFile"

# Display LAPS Prompt dialog
updateScriptLog "Displaying LAPS prompt to user"
LAPSPromptResults=$( eval "${dialogBinary} --jsonfile ${LAPSPromptJSONFile} --json" )

if [[ -z "${LAPSPromptResults}" ]]; then
    LAPSPromptReturnCode="2"
else
    LAPSPromptReturnCode="0"
fi

case "${LAPSPromptReturnCode}" in

    0) # Process exit code 0 scenario here
    # set the variable for the selected item
        selectedUser=$(get_json_value_startPromptDialog "$LAPSPromptResults" "LAPS User" "selectedValue")
        updateScriptLog "LAPS User ${selectedUser} selected."
        ;;
    2) # Process exit code 2 scenario here
        quitScript "1"
        ;;
    *) # Process catch-all scenario here
        quitScript "2"
        ;;
esac

# Use the API to get the password for the selected user

passwordInfomation=$( curl -X 'GET' \
  "${jamfProURL}"/api/v2/local-admin-password/"${managementID}"/account/"${selectedUser}"/password \
  -H 'accept: application/json' \
  -H "Authorization: Bearer ${bearerToken}"
)

password=$(get_json_value "$passwordInfomation" 'password' )

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Results Dialog
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

resultsJSONFile=$( mktemp -u /var/tmp/resultsJSONFile.XXX )
resultsCommandFile=$( mktemp -u /var/tmp/dialogCommandFileResults.XXX )

resultsPromptJSON='
{
    "commandfile" : "'"${resultsCommandFile}"'",
    "title" : "Jamf LAPS via Dialog",
    "icon" : "'"${startIcon}"'",
    "overlayicon" : "'"${overlayicon}"'",
    "iconsize" : "198.0",
    "button1text" : "Quit",
    "ontop" : "true",
    "position" : "center",
    "moveable" : true,
    "titlefont" : "shadow=true, size=36, colour=#FFFDF4",
    "message" : "\n\n **Computer Name:**  \n '${computerName}'  \n\n **Computer Serial:**  \n '${computerSerialNumber}'  \n\n **LAPS User:**  \n '${selectedUser}'  \n\n **Password**  \n '${password}' ",
    "messagefont" : "size=14",
}
'

echo "$resultsPromptJSON" > "$resultsJSONFile"

# Display LAPS Prompt dialog
updateScriptLog "Displaying results to user"
resultsPromptResults=$( eval "${dialogBinary} --jsonfile ${resultsJSONFile} --json" )

if [[ -z "${resultsPromptResults}" ]]; then
    resultsPromptReturnCode="2"
else
    resultsPromptReturnCode="0"
fi

case "${resultsPromptReturnCode}" in

    0) # Process exit code 0 scenario here
        quitScript "0"
        ;;
    2) # Process exit code 2 scenario here
        quitScript "1"
        ;;
    *) # Process catch-all scenario here
        quitScript "2"
        ;;
esac
