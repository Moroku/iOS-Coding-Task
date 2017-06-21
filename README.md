# iOS-Coding-Task
Coding task for iOS Developer Role Applicants 


## The Task
The purpose of this exercise is to showcase your iOS skills to show us you know your stuff.

We've setup a series of tasks for you to complete that will test the things we're looking for.

You'll be communicating with the Moroku GameSystem. The GameSystem Server is a Ruby on Rails application that provides gamification to clients via APIs built here at Moroku. You'll be interacting with GameSystem via our API. Take a look at the [client](http://docs.gamesystemclientapi.apiary.io/#) and [admin](http://docs.gamesystemadminapi.apiary.io/#) API docs. on Apiary.

If something is not clear (or in the unfortunate case, if something is not working) please email dave@moroku.com

### What you get

You'll be given an API token and shared secret to allow making requests to the admin API

We also give you a handy crypto class (described below) to help you build requests for the server

### Let's get started

All of the steps will involve using the Player API docs.

We've created a player for you as well as a rule, a badge and some avatar components.

We'd like you to :

1: Connect to the GameServer and retrieve the player data, render it in an exciting and cool way. Be sure to show the player name, points and any achievements they have unlocked.

2: We created an external event called 'Magic' we'd like you to post that event to the server (maybe in response to a button push).  In your response you should get a message showing that the points total has increased. Show the player that this has happened in an interesting way.

3: We created another external event called 'Rainbow' which will result in the player being awarded with an achievement.  Make a nice animation to show that this happened.

4: Extra Credit!  Players have avatars which have compoenents which have options.  GameServer doesn't care too much waht any of this means. Your Player has an avatar with a 'Top' and 'Bottom' component. 'Top' components have two options, as do 'Bottom' components.  Think of a graphical way to render an avatar based on the specific combination of 'Top' and 'Bottom'.  Allow the player to change these in a graphical way and post the updated avatar details back to teh server.


### Outcomes

It would be great if we could see:

Your resulting app running on an iDevice of your choice

A github repo that we can look at to see your code base

And some tests around some of the functionality you've created


## Encryption

The GameSystem Server uses HMAC encryption to secure API calls.  Documentation is below but in the meantime, we've provided you with a utility class that will help you get started.


Here's how you use it:



	// Grab the API Key
    NSString *apiKey 		= MY_API_KEY;
    NSString *sharedSecret  = MY_SHARED_SECRET;
            
    CryptoUtil *cryptor = [[CryptoUtil alloc] init];
            
    NSDictionary *cryptDict = [cryptor generateHMACWithContent:request.payload
                                                  resourcePath:request.resourcePath
                                                    httpMethod:request.method
                                                     secretKey:sharedSecret];
            
	// Build HTTP request for API
	// Set Content-MD5: header to          [cryptDict objectForKey:kBase64Md5Content]
	// Set Authorization: header to    	  MY_API_KEY:[cryptDict objectForKey:kHmacSha1]
	// Set Date: header to 					[cryptDict objectForKey:kUtcDate]

And submit request.


## HMAC Documentation
The GameSystem Server API is secured with an API key and shared secret. 

The shared secret is used to generate a hashed-key message authentication code (HMAC) which is transmitted with each API request.  On receiving an API request, the Game Server dereferences the API key to obtain the user’s shared secret and then validates the HMAC component of the Authorization field.

The Date: header is then checked to ensure that this API request is ‘current’ i.e. within a 20 seconds of when the message was constructed. The API will use the specified timezone in this date security header and compare it to the server's time (in UTC) so any client app can pass a date in their timezone for the request.


HMAC Generation
1. Construct a MD5 hash of the body payload, if a body  is present, or alternatively of the empty string

2. Set the Content-MD5 header of the request to the base64 encoded representation of the value from step 1

3. Construct a datetime stamp (24-hour clock ranging from 00..23) formatted as "yyyyMMdd HH:mm:ss UTC"

4. Set the Date header of the request to the value from 3

5. Construct plain text by concatenating the following values, in this order, separated by ‘\n’
	* Date-time stamp from step 3
	* Base64 encoded MD5 hash from step 1
	* Resource Path for the API call, any request query parameters should be stripped from the path first. 
	* HTTP method (in upper case)
    
6.  Using the secret key, construct a HMAC-SHA-1 of the plain text from step 5
7.  Set the Authorization header to the value API_KEY : HMAC*


	* API_KEY refers to the value of the client’s API key and the HMAC refers to the  result generated in step 6