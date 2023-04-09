package com.example.knockserver;

import static spark.Spark.*;
import java.util.HashMap;
import java.util.ArrayList;

import org.whispersystems.libsignal.ecc.Curve;
import org.whispersystems.libsignal.ecc.ECPublicKey;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import java.io.ObjectOutputStream;
import java.io.FileOutputStream;
import java.io.ObjectInputStream;
import java.io.FileInputStream;

import java.io.*;
import java.io.File;

import com.google.gson.Gson;

public class App 
{
    static HashMap<String, String> users = new HashMap<String,String>();
    static HashMap<String, HashMap<String, String>> knockRequests = new HashMap<String, HashMap<String, String>>();
    static HashMap<String, HashMap<String, ArrayList<String>>> unreads = new HashMap<String, HashMap<String, ArrayList<String>>>();

    public static void main( String[] args )
    {
        try {
            if (new File("userdb.ser").exists()) {
                ObjectInputStream userOIS = new ObjectInputStream(new FileInputStream("userdb.ser"));
                users = (HashMap<String, String>) userOIS.readObject(); userOIS.close();
            }

            if (new File("knockreqs.ser").exists()) {
                ObjectInputStream reqOIS = new ObjectInputStream(new FileInputStream("knockreqs.ser"));
                knockRequests = (HashMap<String, HashMap<String, String>>) reqOIS.readObject(); reqOIS.close();
            }
        } catch (IOException | ClassNotFoundException e) {
            e.printStackTrace();
        }
        
        ipAddress("0.0.0.0");
        port(56743);
        get("/ping", (request, response) -> "pong");
        get("/save", (request, response) -> {
            try {

                ObjectOutputStream oos = new ObjectOutputStream(
                    new FileOutputStream("userdb.ser")
                );
                oos.writeObject(users);
                oos.flush();
                oos.close();

                oos = new ObjectOutputStream(
                    new FileOutputStream("knockreqs.ser")
                );
                oos.writeObject(knockRequests);
                oos.flush();
                oos.close();

                return true;
            } catch (Exception e) {
                e.printStackTrace();
                response.status(400);
                return "400 Bad Request";
            }
        });
        post("/userExists", (request, response) -> {
            
            try {
                HashMap<Object, Object> requestJson = new Gson().fromJson(request.body(), HashMap.class);
                if (requestJson == null) {
                    response.status(400);
                    return "400 Bad Request";
                }
                return (users.containsKey((String)requestJson.get("username")));
            } catch (Exception e) {
                e.printStackTrace();
                response.status(400);
                return "400 Bad Request";
            }
        });
        post("/addUser", (request, response) -> {
            try {
                HashMap<Object, Object> requestJson = new Gson().fromJson(request.body(), HashMap.class);
                if (requestJson == null) {
                    response.status(400);
                    return "400 Bad Request";
                }

                if (users.containsKey((String)requestJson.get("username"))) {
                    response.status(403);
                    return "403 Username already exists";
                }
                users.put((String)requestJson.get("username"), (String)requestJson.get("pubkey"));

                return true;

            } catch (Exception e) {
                e.printStackTrace();
                response.status(400);
                return "400 Bad Request";
            }
        });
        post("/sendKnockRequest", (request, response) -> {
            
            try {
                HashMap<Object, Object> requestJson = new Gson().fromJson(request.body(), HashMap.class);
                if (requestJson == null) {
                    response.status(400);
                    return "400 Bad Request";
                }
                String requestor = (String) requestJson.get("requestor");
                String requestee = (String) requestJson.get("requestee");
                String knockClient = (String) requestJson.get("knockClient");
                String signature = (String) requestJson.get("sig");

                ECPublicKey requestorKey = Curve.decodePoint(decodeB64((String)users.get(requestor)), 0);
                if (Curve.verifySignature(requestorKey, requestee.getBytes(StandardCharsets.UTF_8), decodeB64(signature))) {
                    // Verified Authenticity

                    // Check if other person already requested
                    if (knockRequests.containsKey(requestor) && knockRequests.get(requestor).containsKey(requestee)) {
                        // Make sure the other guy knows that you accepted
                        if (knockRequests.containsKey(requestee)) {
                            knockRequests.get(requestee).put(requestor, knockClient);
                        } else {
                            HashMap<String, String> tMap = new HashMap<String, String>();
                            tMap.put(requestor, knockClient);
                            knockRequests.put(requestee, tMap);
                        }
                        response.status(202);
                        return knockRequests.get(requestor).get(requestee);
                    }
                    // Nevermind, they're a first time requestor
                    response.status(201);
                    if (knockRequests.containsKey(requestee)) {
                        knockRequests.get(requestee).put(requestor, knockClient);
                    } else {
                        HashMap<String, String> tMap = new HashMap<String, String>();
                        tMap.put(requestor, knockClient);
                        knockRequests.put(requestee, tMap);
                    }
                    return true;
                } else {
                    response.status(403);
                    return "403 Forbidden";
                }
            } catch (Exception e) {
                e.printStackTrace();
                response.status(400);
                return "400 Bad Request";
            }
        });
        post("/getKnockRequestStatus", (request, response) -> {
            
            try {
                HashMap<Object, Object> requestJson = new Gson().fromJson(request.body(), HashMap.class);
                if (requestJson == null) {
                    response.status(400);
                    return "400 Bad Request";
                }
                String requestor = (String) requestJson.get("requestor");
                String requestee = (String) requestJson.get("requestee");
                String signature = (String) requestJson.get("sig");

                ECPublicKey requestorKey = Curve.decodePoint(decodeB64((String)users.get(requestor)), 0);
                if (Curve.verifySignature(requestorKey, requestee.getBytes(StandardCharsets.UTF_8), decodeB64(signature))) {
                    // Verified Authenticity

                    // Is the other person requesting?
                    if (knockRequests.containsKey(requestor) && knockRequests.get(requestor).containsKey(requestee)) {
                        response.status(202);
                    } // Have you already requested?
                    else if (knockRequests.containsKey(requestee) && knockRequests.get(requestee).containsKey(requestor)) {
                        response.status(201);
                    } else {
                        response.status(204);
                    }
                    return true;
                } else {
                    response.status(403);
                    return "403 Forbidden";
                }
            } catch (Exception e) {
                e.printStackTrace();
                response.status(400);
                return "400 Bad Request";
            }
        });
        post("/sendMessage", (request, response) -> {
            
            try {
                HashMap<Object, Object> requestJson = new Gson().fromJson(request.body(), HashMap.class);
                if (requestJson == null) {
                    response.status(400);
                    return "400 Bad Request";
                }
                String sender = (String) requestJson.get("sender");
                String sendto = (String) requestJson.get("sendto");
                String content = (String) requestJson.get("content");
                String signature = (String) requestJson.get("sig");

                ECPublicKey senderKey = Curve.decodePoint(decodeB64((String)users.get(sender)), 0);
                if (Curve.verifySignature(senderKey, decodeB64(content), decodeB64(signature))) {
                    // Verified Authenticity
                    if (unreads.containsKey(sendto)) {
                        if (unreads.get(sendto).containsKey(sender)) {
                            unreads.get(sendto).get(sender).add(content);
                        } else {
                            ArrayList<String> tmpArrayList = new ArrayList<String>();
                            tmpArrayList.add(content);
                            unreads.get(sendto).put(sender, tmpArrayList);
                        }
                    } else {
                        HashMap<String, ArrayList<String>> tMap = new HashMap<String, ArrayList<String>>();
                        ArrayList<String> tmpArrayList = new ArrayList<String>();
                        tmpArrayList.add(content);
                        tMap.put(sender, tmpArrayList);
                        unreads.put(sendto, tMap);
                    }
                    return true;
                    
                } else {
                    response.status(403);
                    return "403 Forbidden";
                }
            } catch (Exception e) {
                e.printStackTrace();
                response.status(400);
                return "400 Bad Request";
            }
        });

        post("/getMessages", (request, response) -> {
            
            try {
                HashMap<Object, Object> requestJson = new Gson().fromJson(request.body(), HashMap.class);
                if (requestJson == null) {
                    response.status(400);
                    return "400 Bad Request";
                }
                String getter = (String) requestJson.get("getter");
                String signature = (String) requestJson.get("sig");

                ECPublicKey getterKey = Curve.decodePoint(decodeB64((String)users.get(getter)), 0);
                if (Curve.verifySignature(getterKey, getter.getBytes(StandardCharsets.UTF_8), decodeB64(signature))) {
                    // Verified Authenticity
                    if (unreads.containsKey(getter)) {
                        String toReturn = new Gson().toJson(unreads.get(getter));
                        unreads.remove(getter);
                        return toReturn;
                    } else {
                        response.status(204);
                        return false;
                    }
                    
                } else {
                    response.status(403);
                    return "403 Forbidden";
                }
            } catch (Exception e) {
                e.printStackTrace();
                response.status(400);
                return "400 Bad Request";
            }
        });


    }

    private static byte[] decodeB64(String base64String) {
        return Base64.getDecoder().decode(base64String);
    }
}
