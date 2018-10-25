import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.SNSEvent;

import java.text.SimpleDateFormat;
import java.util.*;

import java.io.IOException;

import com.amazonaws.services.dynamodbv2.AmazonDynamoDB;
import com.amazonaws.services.dynamodbv2.AmazonDynamoDBClientBuilder;
import com.amazonaws.services.dynamodbv2.document.DeleteItemOutcome;
import com.amazonaws.services.dynamodbv2.document.DynamoDB;
import com.amazonaws.services.dynamodbv2.document.Item;
import com.amazonaws.services.dynamodbv2.document.Table;
import com.amazonaws.services.dynamodbv2.document.UpdateItemOutcome;
import com.amazonaws.services.dynamodbv2.document.spec.DeleteItemSpec;
import com.amazonaws.services.dynamodbv2.document.spec.UpdateItemSpec;
import com.amazonaws.services.dynamodbv2.document.utils.NameMap;
import com.amazonaws.services.dynamodbv2.document.utils.ValueMap;
import com.amazonaws.services.dynamodbv2.model.ReturnValue;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import com.amazonaws.AmazonServiceException;
import com.amazonaws.regions.Regions;
import com.amazonaws.services.dynamodbv2.AmazonDynamoDB;
import com.amazonaws.services.dynamodbv2.AmazonDynamoDBClient;
import com.amazonaws.services.dynamodbv2.document.*;
import com.amazonaws.services.dynamodbv2.document.spec.QuerySpec;
import com.amazonaws.services.dynamodbv2.document.utils.ValueMap;
import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.SNSEvent;
import com.amazonaws.services.simpleemail.AmazonSimpleEmailService;
import com.amazonaws.services.simpleemail.AmazonSimpleEmailServiceClientBuilder;
import com.amazonaws.services.simpleemail.model.*;

import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Iterator;
import java.util.UUID;

import org.apache.commons.codec.binary.Base64;



public class LogEvent implements RequestHandler<SNSEvent, Object> {

  static AmazonDynamoDB client = AmazonDynamoDBClientBuilder.standard().build();
  static DynamoDB dynamoDB = new DynamoDB(client);
  static String tableName = "Users";

  public Object handleRequest(SNSEvent request, Context context) {

    String email = request.getRecords().get(0).getSNS().getMessage();

    String subject = request.getRecords().get(0).getSNS().getSubject();

    long CurrentTime = System.currentTimeMillis()/1000;

    long ExpirationTime = CurrentTime+20*60;

    String timeStamp = new SimpleDateFormat("yyyy-MM-dd_HH:mm:ss").format(Calendar.getInstance().getTime());

    context.getLogger().log("Invocation started: " + timeStamp);

    context.getLogger().log("isEmpty: " + (request == null));

    context.getLogger().log("messangId: " + (request.getRecords().get(0).getSNS().getMessageId()));

    context.getLogger().log("signature: " + (request.getRecords().get(0).getSNS().getSignature()));

    context.getLogger().log("subject: " + (request.getRecords().get(0).getSNS().getSubject()));

    context.getLogger().log("Timestamp: " + (request.getRecords().get(0).getSNS().getTimestamp()));

    context.getLogger().log("size: " + (request.getRecords().size()));

    context.getLogger().log(request.getRecords().get(0).getSNS().getMessage());

    timeStamp = new SimpleDateFormat("yyyy-MM-dd_HH:mm:ss").format(Calendar.getInstance().getTime());

    context.getLogger().log("Invocation completed: " + timeStamp);

    if(CheckDynamoDB(email)) {
      SendEmail(email,createItems(email, subject, CurrentTime, ExpirationTime));
    }

    return null;
  }

  private static String createItems(String id,String subject,long CurrentTime,long ExpirationTime) {

    Table table = dynamoDB.getTable(tableName);
    String token = "";
    try {
      token = createJWT(id,subject,20*60*1000);

      Item item = new Item().withPrimaryKey("id", id)
              .withString("Token", token)
              .withNumber("CurrentTime", CurrentTime)
//              .withStringSet("Authors", new HashSet<String>(Arrays.asList("Author12", "Author22")))
              .withNumber("ExpirationTime", ExpirationTime);
      table.putItem(item);

    }
    catch (Exception e) {
      System.err.println("Create items failed.");
      System.err.println(e.getMessage());

    }
    return token;
  }

  private static String createJWT(String id, String subject, long ttlMillis) throws Exception {
    SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.HS256;
    long nowMillis = System.currentTimeMillis();
    Date now = new Date(nowMillis);
    Map<String, Object> claims = new HashMap<String, Object>();
    claims.put("uid", "001");
    claims.put("user_name", "admin");
    claims.put("nick_name", "jarvisyao");
    SecretKey key = generalKey();
    JwtBuilder builder = Jwts.builder()
            .setClaims(claims)
            .setId(id)
            .setIssuedAt(now)
            .setSubject("{\"id\":\""+subject+"\"}")
            .signWith(signatureAlgorithm, key);
    if (ttlMillis >= 0) {
      long expMillis = nowMillis + ttlMillis;
      Date exp = new Date(expMillis);
      builder.setExpiration(exp);     //expttl
    }
    return builder.compact();
  }

  private static SecretKey generalKey(){
    String stringKey = Constant.JWT_SECRET;
    byte[] encodedKey = Base64.decodeBase64(stringKey);
    System.out.println(encodedKey);
    System.out.println(Base64.encodeBase64URLSafeString(encodedKey));
    SecretKey key = new SecretKeySpec(encodedKey, 0, encodedKey.length, "AES");
    return key;
  }

  private static String SendEmail(String email,String token){
    final String FROM = "assignment8@csye6225-spring2018-yaojiaw.me";
    final String SUBJECT = "Password Reset Email";
    final String HTMLBODY = "<h1>Amazon SES Application for Password Reset</h1>"
            + "<p>The password reset link: " + "<a href='https://aws.amazon.com/ses/'>" + "http://csye6225-fall2017-lijin3.me/reset?email="
            + email + "&token=" + token + "</a>";
    final String TEXTBODY = "This email was sent through Amazon SES "
            + "using the AWS SDK for Java.";
    try {
      AmazonSimpleEmailService client =
              AmazonSimpleEmailServiceClientBuilder.standard()
                      .withRegion(Regions.US_EAST_1).build();
      SendEmailRequest sendEmailRequest = new SendEmailRequest()
              .withDestination(
                      new Destination().withToAddresses(email))
              .withMessage(new Message()
                      .withBody(new Body()
                              .withHtml(new Content()
                                      .withCharset("UTF-8").withData(HTMLBODY))
                              .withText(new Content()
                                      .withCharset("UTF-8").withData(TEXTBODY)))
                      .withSubject(new Content()
                              .withCharset("UTF-8").withData(SUBJECT)))
              .withSource(FROM);
      client.sendEmail(sendEmailRequest);
      System.out.println("Email sent successfully!");
    } catch (Exception ex) {
      System.out.println("The email was not sent. Error message: "
              + ex.getMessage());
    }
    return "SendEmail() finished";
  }

  private static boolean CheckDynamoDB(String email) {
    Table table = dynamoDB.getTable(tableName);
    QuerySpec spec = new QuerySpec().withKeyConditionExpression("id = :email")
            .withValueMap(new ValueMap().withString(":email", email));

    ItemCollection<QueryOutcome> items = table.query(spec);

    Iterator<Item> iterator = items.iterator();
    Item item = null;
    while (iterator.hasNext()) {
      item = iterator.next();
      System.out.println(item.toJSONPretty());
    }
    if (item == null) {
      return true;
    } else return false;
  }

}

