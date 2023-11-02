# Admin-cli
 *The Admin-cli challenge was labelled "remote"*

It was solved by relatively few teams, 6-7% of teams getting points.

## The problem
The description was: 
"A (very) early version of the administration tool used for FE-CTF was found. Looks like they only just started making it, but maybe it's already vulnerable?"
The Download contained a `Dockerfile`and a `Main.java`

```Dockerfile
FROM ubuntu:22.04

RUN apt update -y
RUN apt install -y wget openjdk-19-jdk unzip socat

USER nobody

WORKDIR /tmp
RUN wget http://archive.apache.org/dist/logging/log4j/2.14.1/apache-log4j-2.14.1-bin.zip
RUN unzip apache-log4j-2.14.1-bin.zip

COPY Main.java .
RUN javac -cp '/tmp/apache-log4j-2.14.1-bin/log4j-api-2.14.1.jar:/tmp/apache-log4j-2.14.1-bin/log4j-core-2.14.1.jar' Main.java
CMD socat -v tcp-listen:1337,fork,reuseaddr system:"java -cp '.:/tmp/apache-log4j-2.14.1-bin/log4j-api-2.14.1.jar:/tmp/apache-log4j-2.14.1-bin/log4j-core-2.14.1.jar' Main",stderr
```

And the `Main.java` file:
```java
import java.util.Base64;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.Scanner;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.core.config.Configurator;


public class Main {

	/* flag{....} */
	private static String API_KEY = Base64.getUrlEncoder().encodeToString(System.getenv("FLAG").getBytes());
	
	/* Doesn't seem to be authorized, I don't know why... */
	/* https://backend.fe-ctf.local/removePoints?teamId=0&amount=1000&key=api_key */
	private static int HASH_CODE = -615519892;

	/* Should be safe, right? */
	private static Logger logger = LogManager.getLogger(Main.class);
	
	public static void main(String[] args) {
		Configurator.setLevel(Main.class.getName(), Level.INFO);
		Scanner s = new Scanner(System.in);
		System.out.print("Enter URL: ");
		String input = s.nextLine();
		s.close();
		try {
			URL url = new URL(input.replaceAll("API_KEY", API_KEY));
			if (url.hashCode() == HASH_CODE && url.getHost().equals("backend.fe-ctf.local")) {
				logger.info("URLs Matched, sending request to {}", url);
				/* TODO: Figure out how to send request
				HttpURLConnection con = (HttpURLConnection) url.openConnection();
				con.setRequestMethod("GET")
				*/
			} else {
				logger.warn("URLs are not equal!");
			}
		} catch (MalformedURLException e) {
			logger.error("Invalid URL");
			System.exit(1);
		}
	}
}
```

### Initial analysis
So we need to attack a server, which is running a vulnerable version of log4j.

Looking down over the code, we can see 2 calls to logger with a fixed string, and one that reflects the url. 
To hit the line reflecting the url, we need to pass the ```if (url.hashCode() == HASH_CODE ...``` check, and looking at the line above
```URL url = new URL(input.replaceAll("API_KEY", API_KEY));``` we can see that if we can insert API_KEY in the URL, it will be replaced by the flag (variable `API_KEY`) and it will be reflected back to us.

Thus the vulneable log4j was just a decoy.

Now, the task is to find a way to bypass the `hashCode()` validation, and insert the string `API_KEY` somewhere in the URL. 

## Solving the problem

### Looking in the docs
On a normal Java object, `hashCode()`returns a 32-bit integer, which can be used for hashtables. Let us see how it is calculated for URLs.
Looking at the Java.Net.URL documentation https://docs.oracle.com/javase/8/docs/api/java/net/URL.html, we see:

>public int hashCode()
>
>Creates an integer suitable for hash table indexing.
>
>The hash code is based upon all the URL components **relevant** for URL comparison. As such, this operation is a blocking operation.

The term relevant has been emphasized by me. The implication of this term *relevant* implies that there are *irrelevant* part(s) of the URL when it comes down to calculating the hashcode

This was clearly a hint at the correct solution. 

### Looking at source code - Java.Net.URL

https://github.com/openjdk/jdk/blob/master/src/java.base/share/classes/java/net/URL.java this one is boring, it just calls the `handler.hashCode()`
So move on the `Java.Net.URLStreamHandler()` source

### Looking at source code - Java.Net.URLStreamHandler

https://github.com/openjdk/jdk/blob/master/src/java.base/share/classes/java/net/URLStreamHandler.java

Here we can see that hashcode consists of the sum of: `protocol.hashCode() + addr.hashCode() + file.hashCode() + ref.hashCode() + u.GetPort()`

The fact that the port number (0..64k) is used as a number directly in the sum basically means that the complexity of creating a collision has been reduced from 32 bits to 16 bits, as we could pick a random port number. 

This is nice to know, but not the *irrelevant* part we were looking for.

So we continue looking at the source. We have one function `protected void parseURL(URL u, String spec, int start, int limit)` early in the file where we can see what fields (or rather components) are extracted from the URL.

First it strips off the query string, then it looks at authority.

`host = authority = spec.substring(start, i);`

then it looks for @ `if (ind != authority.lastIndexOf('@')) {`

And we can see that it extracts the username:password from host field - and then removes that part from the host used for `hashCode()`

```java
            host = authority = spec.substring(start, i);

            int ind = authority.indexOf('@');
            if (ind != -1) {
                if (ind != authority.lastIndexOf('@')) {
                    // more than one '@' in authority. This is not server based
                    userInfo = null;
                    host = null;
                } else {
                    userInfo = authority.substring(0, ind);
                    host = authority.substring(ind+1);
                }
```
So that is what is the irrelevant component to store for a URL - The username and password - We don't want that in the logfile or in the cache.

RFC-1738 describes URLs as well, as having this after protocol: `//<user>:<password>@<host>:<port>/<url-path>`

Thus we try to insert API_KEY@ in the sample URL `https://API_KEY@backend.fe-ctf.local/removePoints?teamId=0&amount=1000&key=api_key`

Then we try it:
```
~$ nc admin-cli.hack.fe-ctf.dk 1337
Enter URL: https://API_KEY@backend.fe-ctf.local/removePoints?teamId=0&amount=1000&key=api_key
11:55:37.288 [main] INFO  Main - URLs Matched, sending request to https://ZmxhZ3tVTjNYUDNDVDNEXzNYRjFMVFI0VDEwTn0=@backend.fe-ctf.local/removePoints?teamId=0&amount=1000&key=api_key
```

Yes, our URL changed, we have a flag before the @ - but it is not compliant with the flag format. 
Since it is web it could be base64 encoded, and the = in the end helps make this likely. So base64 decode the username, and you will get:
flag{UN3XP3CT3D_3XF1LTR4T10N}

Lots of point :-)




