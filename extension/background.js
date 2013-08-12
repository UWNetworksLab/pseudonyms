// Copyright (c) 2012 
// this module is written upon the codebase of MILK (fixed some bad bugs btw), and changed into a different architecture

// Logging switch
var DEBUG = new Boolean(1);

// Global storage for pseudonym ID list
var pId_list = ['Pub','Root','Isolated','NewTab','Unknown','ThirdParty'];
// Global storage for tabId->PId(Pseudonym ID) mappings.
var tab_arr = {};
// Global storage for reqId->PId(Pseudonym ID) mappings.
var req_arr = {};
// Global storage for tabId->domain mappings.
var tab_domain = {};
// Global storage for tabId->openerTabId mappings (note the difference between chrome API's tab.openerTabId)
// chrome API's tab.openerTabId: the id of tab which you stay before open a new tab
// ours openerTabId here: the id of tab in which you click a link to open a new tab, if use open a new tab manually, the openerTabId = "NoONe"
var tab_openerTab ={};

//Stores information about sites that are in the root store.
var root_store = new Array();
//Stores IPv6 pool and its pseudonym Mapping;
var ip_pool = new Array();

//Logs anytime a cookie is changed.
chrome.cookies.onChanged.addListener( 
    function(info) {
	if(DEBUG) {
            //console.log("onChanged" + JSON.stringify(info));
	}
        
        //Whenever a cookie is updated, we need to send the updated cookie to every tab that should be able to read it via javascript (and the cookie has httpOnly set to false)
        
        //Only update the tabs if the cookie is not http only (security concern: javascript should not reach these cookies)

        if( info.cookie.httpOnly){
            //console.log("a httpOnly cookie: " + info.cookie.name + " = " + info.cookie.value + " domain: " + info.cookie.domain);
            return;
        }

        var cookiePId = getPIdfromCookie(info.cookie.name);
        
        //if it has PID then do nothing.
        if( cookiePId == null )
        {
            //TODO: assign a Isolated pid to it
            console.log("cookiePID = null, info.cookie.name:"+ info.cookie.name + " , todo: assign a Isolated pid to it");
            return;
        }

        if(cookiePId == 'Isolated') return;
        
        
        //remove key from name
        var name = info.cookie.name.substring(getKeyfromPId(cookiePId).length, info.cookie.name.length);
        
        //Get the list of tabs associated with that key
        tabIds = getTabIdsfromPIds(getQualifyPIds(cookiePId));
        
        //console.log("gonna transport some cookies: tabIds(N):"+tabIds.length + " list:" + tabIds.toString());

        //for every tab associated with that key, send the update
        for( var i in tabIds ){
            var request = {cookieName: name, cookieValue: info.cookie.value, isRemoved : info.removed, PId : cookiePId};
            
            
            if( tabIds[i] >= 0){
                //console.log("Sending update message to tab " + tabIds[i]);
                //console.log("Key is: " + key);
                //console.log("Name is: " + name);
                chrome.tabs.sendMessage(parseInt(tabIds[i]), request);//, function(response){console.log(response.farewell)});
            }
        }
       
    });


function assignCookiePId(reqPId, details, i)
{

    cookieRaw = details.responseHeaders[i].value;
    var cookieParts = cookieRaw.split(';');

    var isSameDomain = 1;

    for( var i=0; i<cookieParts.length; i++){
        if(cookieParts[i].length == 0)
            continue;
    
        //remove the whitespace
        var cString = cookieParts[i].replace(/^\s+|\s+$/g,"");
        var splitIndex = cString.indexOf("=");
        var namePart = cString.substring(0, splitIndex);
        var valuePart = cString.substring(splitIndex+1, cString.length);
        
        if(namePart == "domain"){
            if(valuePart.indexOf(tab_domain[details.tabId]) < 0 ){
                isSameDomain = 0;
            }
            //console.log("cookieDomain:" + valuePart + " tab_domain:" + tab_domain[details.tabId] + " isSameDomain:" + isSameDomain);
            if(isSameDomain == 0) return "ThirdParty";

        }
    }
    return reqPId.split('&')[0];
}

// Logs all response headers containing Set-Cookie 
chrome.webRequest.onHeadersReceived.addListener(
    function(details) {
        var reqPId = req_arr[details.requestId];
        if(reqPId == undefined) reqPId = 'Unknown';
        else delete req_arr[details.requestId];

        for(var i in details.responseHeaders) {
            //check if this response header is for setting cookies.
            if(details.responseHeaders[i].name.toLowerCase() == 'set-cookie') {
            if(DEBUG) {
                        //console.log('Logging cookie header before modification.');
                        //console.log(details.responseHeaders[i].value);
		    }
                
                //Just append the key to the front of the header value. This works because the cookie's name is the first entry in the value string.
                var cookiePId = assignCookiePId(reqPId, details, i);
                details.responseHeaders[i].value = getKeyfromPId(cookiePId) + details.responseHeaders[i].value;
                if(DEBUG) {
                    //console.log('Logging the cookie header after modification.');
                    //console.log(details.responseHeaders[i].value);
		        }
            }
        }
        
        return  { responseHeaders:details.responseHeaders };
    },
    {urls: ["<all_urls>"]},
    ["blocking", "responseHeaders"]);


// Logs all response headers containing Set-Cookie. This function will record any header modifications we make in our onHeadersReceived listener.
chrome.webRequest.onCompleted.addListener(
    function(details) {
        for(var i in details.responseHeaders) {
            if(details.responseHeaders[i].name.toLowerCase() == 'set-cookie') {
            
		if(DEBUG) {
                    //If we made any changes to the header, they should show up here.
                    //console.log('Logging the cookie headers upon completion of webrequest');
                    //console.log(details.responseHeaders[i]);
		}
            }
        }
    },
    {urls: ["<all_urls>"]},
    ["responseHeaders"]);

// Logs all request headers containing Cookies. This function will record any header modification we make in our "onBeforeSendHeaders" listener.
chrome.webRequest.onSendHeaders.addListener(
    function(details) {
        for(var i in details.requestHeaders) {
            if(details.requestHeaders[i].name.toLowerCase() == 'cookie') {
		if(DEBUG) {
                    //console.log('Logging the cookie headers upon sending.')
                    //console.log(details.requestHeaders[i]);
		}
            }
        }
    },
    {urls: ["<all_urls>"]},
    ["requestHeaders"]);

//Splits cookie strings of the format "name=value"
function splitCookieString(cookie) {
    if(cookie.indexOf('###') != -1)
        console.error("PID might not be striped from cookie: " + cookie);

    var index = cookie.indexOf('=');
    
    var name = cookie.substring(0, index);
    //Add the +1 to skip the '='
    var value = cookie.substring(index+1, cookie.length);
    
    return {'name':name, 'value':value};
}

var requestOrdinal = 0;

var current_ip_idx = 0;

// Modifies the headers to only include the cookies we want
chrome.webRequest.onBeforeSendHeaders.addListener(
    function(details) {
        var reqPId = getPseudoId(details.tabId, details.url);
        req_arr[details.requestId] = reqPId;
        var cString = "";
        var cDict = {};

        var cookieOriginal_N = 0;
        var cookieUnchanged_N = 0;
        var cookieNoPId_N = 0;
        var cookieDenied_N = 0;
        
        // Find all of the cookies
        for(var i in details.requestHeaders) {
            if(details.requestHeaders[i].name.toLowerCase() === 'user-agent') {
                details.requestHeaders[i].value += " Bind/" + ip_pool[current_ip_idx].ip;
                current_ip_idx = (current_ip_idx + 1) % ip_pool.length;
            }

            if(details.requestHeaders[i].name.toLowerCase() === 'cookie') {

                //Cookie(s) found, we need to split the string to get all of the cookies. Cookie value strings will look like "key1=value1; key2=value2; ..."
                var cookiesRaw = details.requestHeaders[i].value.split(";");
                cookieOriginal_N = cookiesRaw.length;
                
                if(DEBUG) {
                    //console.log('Old cookie Header:' + cookiesRaw.length);
                    //console.log(details.requestHeaders[i].value);
	            }

                //remove the old cookie header from the request. We will add a new one later if needed.
                details.requestHeaders.splice(i, 1);
                
                for(var j in cookiesRaw){
                    //remove the whitespace.
                    cookie = cookiesRaw[j].replace(/^\s+|\s+$/g,"");
                    
                    cookiePId = getPIdfromCookie(cookie);
                                        
					// see if the req could use this cookie with their PIDs 
                    if(cookiePId != null && examPIdRelation(reqPId,cookiePId).approved){

                        //Add a semicolon, if needed, to separate the cookies we have already processed.
                        if( cString.length > 0 ){
                            cString = cString + "; "; 
                        }
                        
                        var matches = cookie.match('###PID\-+[.A-Za-z0-9]+###');

                        //remove the key prefix before sending to the server so the cookie will have a name the server expects.
                        cookie = cookie.substring(matches[0].length, cookie.length);
                        
                        var cookieSplit = splitCookieString(cookie);
                        
                        if(!cDict[cookieSplit.name]){
                            cDict[cookieSplit.name] = cookieSplit.value;
                        }
                        
                        //Append the current cookie to the cookie header string.
                        cString = cString + cookie;

                        cookieUnchanged_N = cookieUnchanged_N + 1;
                    }
                    //Check if the cookie doesn't have a prepended domain key.
                    else if( cookiePId == null){
                        if(DEBUG) {
                            //console.log("Sending unkeyed cookie");
                            //console.log(cookie);
                        }
                        
                        if( cString.length > 0 ){
                            cString = cString + "; "; 
                        }

                        var cookieSplit = splitCookieString(cookie);
                        
			            if(DEBUG) {
                                        if(cDict[cookieSplit.name]){
				            //console.log('Already found another cookie with this name. Overwriting with this cookie.');
                                        }
			            }
                        
                        cDict[cookieSplit.name] =cookieSplit.value;
                        
                        //We need to update the cookie to add the key!
                        cString = cString + cookie;

                        //append the PID key
                        var keyedName = getKeyfromPId(reqPId)+cookieSplit.name;
                        
                        //rewrite the cookie in the cookie store to bind it to the current PID.
                        //This  call appears to be causing a race condition. Commenting it out for testing.
                        rewriteCookie(cookieSplit.name,keyedName,details.url, requestOrdinal++);
                        
                        cookieNoPId_N = cookieNoPId_N + 1;
                    }
                    else
                    {
                        //console.log("cookie denied: reqPId: " + reqPId + " cookiePId: " + cookiePId);    
                        cookieDenied_N = cookieDenied_N + 1;
                    }
                }


                cString = '';
                
                for(var i in cDict){
                    if( cString.length > 0 ){
                        cString = cString + "; "; 
                    }
                    
                    cString = cString + i + '='+ cDict[i];
                }
                
                //If we found any cookies with the appropriate domain key, then we add the new header to the request.
                if( cString.length > 0 ) {
                    var cookieHeader = {name:"Cookie", value:cString};
                    details.requestHeaders.push(cookieHeader);
                    if(DEBUG) {
                        //console.log('Request ' + details.requestId +  ':' + cookieOriginal_N + '(removed) ' + cookieUnchanged_N + '(good) ' + cookieDenied_N + '(deny) ' + cookieNoPId_N + '(noPID)');
                        //console.log('cookiesRaw:' + cookiesRaw.toString());
                        //console.log('cookiesNew:' + cookieHeader.value.toString());
                    }
                }
            }
        }
        

        return  { requestHeaders:details.requestHeaders };
    },
    {urls: ["<all_urls>"]},
    ["blocking", "requestHeaders"]);


function getQualifyPIds(pId)
{
    var qPIds = [];
    for(var i in pId_list){
        if(examPIdRelation(pId_list[i],pId).approved) qPIds.push(pId_list[i]);
    }
    return qPIds;
}


//resPId should be on the tree of actPId
function examPIdRelation(actPId, resPId)
{
    if(actPId == null || actPId == null){
        if(actPId == null) console.error("actPId == null");
        if(actPId == null) console.error("actPId == null");
        return {approved:false,reason:"null"};
    }

    if(actPId == 'Root')
        return {approved:true,reason:"Root"};

    if(resPId == 'Pub')
        return {approved:true,reason:"Pub"};

    if(actPId.split("&").indexOf(resPId) >= 0)
        return {approved:true,reason:resPId}; 
    
    return {approved:false,reason:"Unknown"};
}


function getPIdfromCookie(cookie)
{
    var matches = cookie.match('###PID\-+[.A-Za-z0-9]+###');

    //assume the key is the first match
    if(matches == null || cookie.indexOf(matches[0]) != 0) {
        console.log("matches == null . cookie: " + cookie);
        return null;
    } else {
        return getPIdfromKey(matches[0]);
    }
}


function getPIdfromKey(key)
{
    //Our key format is '###PID-[.a-zA-Z0-9]###', where [] is the pseudonym ID
    return key.substring(7,key.length-3);
}



function getKeyfromPId(PId)
{
    return "###PID-" + PId + "###";
}

// This function gets the pseudonym Id for the current cookie. 
function getPseudoId(tabId, url){
    //also set tab_arr here!!!
    //We have to check for this because the webrequest listener fires before the tabs listener and thus this will be undefined for the first webrequest from a given tab.
    var pId;
    if(tab_arr[tabId] == undefined){
        if(DEBUG) {
            //console.log(tab_arr[tabId]);
            //console.log(url);
        }
        pId = getDomain(url);
        pId = 'Tab' + tabId;
        tab_arr[tabId]=pId; 
    }
    if(tab_arr[tabId] == "newtab")
    {
        pId = 'NewTab'
        tab_arr[tabId] = tab_arr[tabId]; 
    }
    else
    {
        pId = tab_arr[tabId];
    }
    //console.log(tab_arr[tabId]);
    return  pId;
}





// This function gets all tab ids associate with a given key
function getTabIdsfromPIds(pIds){
    var tabIds = [];
    
    for(var i in pIds){
        for(var tabId in tab_arr){
            //TODO: If key is in root store, send to all tabs.
            if( (tab_arr[tabId]) == pIds[i] && tabIds.indexOf(tabId) == -1){
                    tabIds.push(tabId);
            }
        }
    }
    return tabIds;
}


var updateLog = {};

/*
//This function is supposed to keep some sort of ordering on cookie updates. I am not sure it is actually needed. -RJW
function mostRecentUpdate(keyed_name, url, ordinal){
    if(DEBUG) {
	//console.log("Current request ordinal: " + ordinal);
    }
    
    domain = getDomain(url);
    if(DEBUG) {
	//console.log("For " + domain + " " + keyed_name);
    }
    if(!updateLog[domain]){
	if(DEBUG) {
            //console.log("Adding domain: " + domain + " to the update log.");
	}
        updateLog[domain] = {};
    }
    
    if(!updateLog[domain][keyed_name]){
	if(DEBUG) {
            //console.log("Adding cookie key: " + keyed_name + " to the updateLog[" + domain + "].");
	}
        updateLog[domain][keyed_name] = -1;
    }
    
    if(updateLog[domain][keyed_name] < ordinal){
        updateLog[domain][keyed_name] = ordinal;
	if(DEBUG) {
            //console.log("Most recent update.");
	}
        return true;
    }
    else{
	if(DEBUG) {
            //console.log("Old update");
	}
        return false;
    }
}
*/

// Replace unkeyed cookies with a keyed version.
function rewriteCookie(name, keyed_name, url, ordinal) {
    //make sure this is the most recent update
    //if( !mostRecentUpdate(keyed_name, url, ordinal) ){
    //    return;
    //}
    
    // Get the unkeyed cookie
    chrome.cookies.get({"url": url, "name": name}, function(details) {
	
	if(details == null) {
	    //console.log('No cookies found with details: ');
	    //console.log(name +  ' ' + keyed_name + ' ' + url);
	    return;
	}
	if(DEBUG) {
	    //console.log("Changing cookie " + name + " to " + keyed_name + " for url: " + url);
	}
	// Delete the existing cookie from the CookieStore
	chrome.cookies.remove({"url": url, "name": name});
	// Add the new, keyed version to the CookieStore
	chrome.cookies.set({"url": url, "name": keyed_name, "value": details.value, "domain": details.domain, "path": details.path, "secure": details.secure, "httpOnly": details.httpOnly, "expirationDate": details.expirationDate});
	if(DEBUG) {
	    //console.log(details);
	}
    }
)
}

function getCookieStringFromStore(url, tabId, sendResponse) {
    //get all cookies for a given domain for a given key
    var tabPId = getPseudoId(tabId, url);
    var cString = "";
    
    chrome.cookies.getAll({"url": url}, function(cookies) {

        //Check to see if we have any cookies to deal with. If not just return
        if(cookies == null || cookies.length == 0) {
            //console.log('No cookies found with details: ' + url);
            return;
        }
        
        //console.log("Getting cookies for " + cKey);
        //console.log("domain" + getDomain(url));
        
        for( var i in cookies ){

            
            //Check if the cookie's prepended key matches what we expect,
            var cookiePId = getPIdfromCookie(cookies[i].name);
        
            var isHttpOnly = cookies[i].httpOnly;
            
            if(isHttpOnly == true)
                continue;
            else if(cookiePId == null){
                console.log("discover weird cookie here: " + cookies[i].name + "=" + cookies[i].value);
                chrome.cookies.remove(cookies[i]);
                continue;
            } else if( examPIdRelation(tabPId,cookiePId).approved){
                //console.log("Adding cookie to string");
            
                
                var matches = cookies[i].name.match('###PID\-+[.A-Za-z0-9]+###');
                
              
                //remove the key prefix
                name = cookies[i].name.substring(key.length, cookies[i].name.length);
        
                //Add a semicolon, if needed, to separate the cookies we have already processed.
                if( cString.length > 0 )
                    cString += "; "; 
                
                cString += (name +  "=" + cookies[i].value);
            }
                
        }
        
        //console.log(cString);
        
        sendResponse(cString);
        
    });
}

// update tab PId
function assignTabPId(tab)
{
    tabId = tab.id;
    
    // Associate the tabId with the current tab URL to track the current domain that should be able to fetch cookies.
    domain = getDomain(tab.url);
 
   
    if(tab_domain[tabId] == undefined || tab_domain[tabId] == "chrome://newtab/" || tab_domain[tabId] == "chrome://newtab"){
        // Associate the tabId with a pseudonym ID
        tab_arr[tabId] = getPseudoId(tabId,tab.url);
        //note :null is also undefined
        if(tab_openerTab[tab.id] == undefined || tab_arr[tab_openerTab[tab.id]] == undefined){ //TODO:figure out why 2nd argument is needed 
                
        }else if(tab_openerTab[tab.id] == "NoOne"){
            //search for tabs with same domain, give user the options to link with those tabs
            for(var i in tab_domain){
                if(domain == tab_domain[i]){
                }
            }
        }else{
            var openerPIds = tab_arr[tab_openerTab[tab.id]].split("&");
            var currentPIds = tab_arr[tabId].split("&");
            for(var i in openerPIds){
                if(currentPIds.indexOf(openerPIds[i]) < 0){
                    tab_arr[tabId] = tab_arr[tabId] + "&" + openerPIds[i];
            }
        }
            // release     
            delete tab_openerTab[tab.id];         
        }
    }
    else if(tab_domain[tabId] != domain){
        tab_arr[tabId] = getPseudoId(tabId,tab.url);
    }
    else{ //tab_domain[tabId] == domain
        
    }
    tab_domain[tabId] = domain;

    chrome.pageAction.setTitle({tabId: tab.id, title: "id:"+tab.id+"domain:"+tab_domain[tabId] +"PID:"+tab_arr[tabId]});
}

// A listener that fires whenever a tab is created to show page action button
chrome.tabs.onCreated.addListener(
    function(tab){
        tabId = tab.id;

        if(tab.title == "New Tab") {
            tab_openerTab[tab.id] = "NoOne";
            //console.log("New Tab");
        }
        else tab_openerTab[tab.id] = tab.openerTabId;

        //console.log("title:" + tab.title + "|" + "opener ID:" + tab.openerTabId);
        chrome.pageAction.setTitle({tabId: tab.id, title: ""+tab.id});
        chrome.pageAction.show(tab.id);

        
        //console.log("tab created. domain:" + getDomain(tab.url) + "  url:" + tab.url);
        
        //update tab pid so all requests can happen with correct pid
        if(tab.title != "New Tab") assignTabPId(tab);

    
    }
);

// A listener that fires whenever a tab is updated to check the URL.
chrome.tabs.onUpdated.addListener(
    function(tabId, changeInfo, tab) {
        
        /*
        // Change tab name
        if(tab.title.indexOf("" + tabId) != 0) //prevent repeated change
        {
            // Change tab name
            var name = tabId + " " + tab.title;
            //chrome.tabs.executeScript(tabId, {code: 'if(document != undefined && document.title != undefined)' + 'document.title = "'+ name + '";'}, null);
        }
        */


        //console.log("tab updated. domain:" + getDomain(tab.url) + "  url:" + tab.url);
        assignTabPId(tab);
        chrome.pageAction.show(tab.id);
        
        return tab;
    }
);

// A listener that removes removed tabs from the tab_arr array
chrome.tabs.onRemoved.addListener(
    function(tabId, removeInfo) {
        //Remove the tab Id and it's domain association from the domain store
        delete tab_arr[tabId];
    
    }

);
// Listen for messages from the content scripts.
chrome.extension.onMessage.addListener(
    function(request, sender, sendResponse) {
        if (request.type == "cookieBootstrap") {  
	    if(DEBUG) {
		//console.log("Bootstrapping the cookies for the page load.");
	    }
            getCookieStringFromStore(request.url, sender.tab.id, sendResponse);
        }
        else if(request.type == "setCookie") {
	    if(DEBUG) {
		//console.log("Setting cookie received from javascript: " + request.cookieRaw);
	    }
            parseAndStoreRawCookie(sender.tab.id, request.url, request.cookieRaw);
            sendResponse("blah");
        }
		else if(request.type == "login") {
			//	//// Add the domain to the root store if it is not already there.
			//	if(root_store.indexOf(getDomain(request.domain)) == -1) {
			//	    root_store.push(getDomain(request.domain)); 
			//	} 
			//	console.log("Login: Root store contains " + root_store); 
	    }
        return true;
		}
);


//Parses the raw cookie string passed from the content script. 
//This is the cookie string that is normally parsed by document.cookie. 
//In essence, this function implements the functionality of document.cookie.
function parseAndStoreRawCookie(tabId, url, cookieRaw){
    if(DEBUG) {
	//console.log("Attempting to parse raw cookie string: " + cookieRaw);
    }
    var cookieObj = {};
    cookieObj.url = url;
    
    var cKey = getKeyfromPId(getPseudoId(tabId, url).split("&")[0]);
    
    var cookieParts = cookieRaw.split(';');

    if(DEBUG) {
	//console.log(cookieParts);
    }

    for( var i=0; i<cookieParts.length; i++){
        if(cookieParts[i].length == 0)
            continue;
    
        //remove the whitespace
        var cString = cookieParts[i].replace(/^\s+|\s+$/g,"");
    
        var splitIndex = cString.indexOf("=");
        
        var namePart = cString.substring(0, splitIndex);
        var valuePart = cString.substring(splitIndex+1, cString.length);
        
        
        //first part is the name value pair
        if( i == 0 ){
            cookieObj.name = cKey + namePart;
            cookieObj.value = valuePart;
        }
        else if( namePart.toLowerCase() == "path" ){
            cookieObj.path = valuePart;
        }
        else if( namePart.toLowerCase() == "domain" ){
            cookieObj.domain = valuePart;
        }
        //else if( partSplit[0].toLowerCase() == "max-age" ){
            //not sure what to do here....
        //}
        else if( namePart.toLowerCase() == "expires" ){
            //convert the gmt string to seconds since the unix epoch
            var date = new Date(valuePart);
            cookieObj.expirationDate = date.getTime() / 1000;
            if(cookieObj.expirationDate == NaN){
                console.log("reserve here to catch bug");
                //console.log("valuePart:" + valuePart);
            }
        }
        else if( cString == "secure" ){
            //attention! secure property is not a key-value pair
            cookieObj.secure = true;
        }
        else{
            console.log("set Raw Unknown part!!!! cookie: " + cString); 
        }
    }
    if(DEBUG) {
	//console.log(cookieObj);
    }
    chrome.cookies.set(cookieObj);
}

//Gets the domain from the URL
function getDomain(url) {
    //TODO: Not sure what happens when you specify an IP address.
    pathArray = url.split('/');
    if(pathArray.length < 2){
	if(DEBUG) {
            //console.log('Failed to parse url string: ' + url);
	}
        return url;
    }
    
    pathArray = pathArray[2].split('.');

    //works three letter domain names, e.g. those used for US sites like Google.com and UMass.edu
    if(pathArray[pathArray.length-1].length == 3) {
        return pathArray[pathArray.length-2]+'.'+pathArray[pathArray.length-1]
    } 
    //works for co.uk and similar domain names.
    else if(pathArray[pathArray.length-1].length == 2) {
        return pathArray[pathArray.length-3]+'.'+pathArray[pathArray.length-2]+'.'+pathArray[pathArray.length-1];
    }
    if(DEBUG) {
	//console.log('Failed to parse url string: ' + url);
    }
    return url;
}

function getScope() {
//TODO: deal incognito mode
//return 'incognito_persistent';
    return 'regular';
}

function setProxy(proxy_address) {
    var proxy_ip = proxy_address.split(':')[0];
    var proxy_port = proxy_address.split(':')[1];

    //TODO:https
    var proxy = {scheme: 'http',
                 host:   proxy_ip,
                 port:   parseInt(proxy_port)};
    
    var proxysettings = {
      mode: 'fixed_servers',
      rules: {}
    };

    proxysettings.rules['proxyForHttp'] = proxy;

    chrome.proxy.settings.set({
      'value': proxysettings,
      'scope': getScope()
    }, function() {});
}



chrome.extension.onMessage.addListener(
  function(request, sender, sendResponse) {
    cmd_detail = request['cmd'].split('=');
    if (cmd_detail[0] == 'proxy') {
        setProxy(cmd_detail[1]);
    } else if (cmd_detail[0] == 'ip') {
        if(cmd_detail[1] == 'refresh'){
           sendResponse(JSON.stringify(ip_pool));
        }else if(cmd_detail[1] == 'request'){
           req = new XMLHttpRequest();
           function re(){
             if(req.readyState==4){
               a = new Object();
               a.pseudonym = "not_assigned";
               a.ip = req.responseText.split(';')[1];
               ip_pool.push(a);
               chrome.tabs.sendMessage(sender.tab.id, {greeting: "ip obtained!"});
             }
           }
           req.onreadystatechange = re;
           reqString = "http://iloveipv6privacyweb.edu/1234567890"+Math.random().toString().substring(2,7)+".test";
           console.log(reqString);
           req.open(
                "GET",
                reqString,
                     true);
            req.send(null);
        }
        else console.log('wrong message, cmd_detail[1]');
    } else {
        console.log('wrong message, cmd_detail[0]');
    }
  });

//setProxy();

//test on getDomain()
/*
console.log(getDomain("www.google.com"));
console.log(getDomain(".www.google.com"));
console.log(getDomain("fdsf.www.google.com"));
console.log(getDomain("fdsf.google.com"));
console.log(getDomain(".fdsf.google.com"));
console.log(getDomain("http://fdsf.google.com"));
console.log(getDomain("https://fdsf.google.com"));
console.log(getDomain("ftps://fdsf.google.com/fsdf/dsf"));
console.log(getDomain("ftps://fdsf.google.com/fsdf/"));
*/
