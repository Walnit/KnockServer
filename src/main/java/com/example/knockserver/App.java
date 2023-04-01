package com.example.knockserver;

import static spark.Spark.*;
import java.util.HashMap;

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

        post("/save", (request, response) -> {
            try {
                HashMap<Object, Object> requestJson = new Gson().fromJson(request.body(), HashMap.class);
                if (requestJson == null) {
                    response.status(400);
                    return "400 Bad Request";
                }
                if (((String)requestJson.get("pw")).equals("pauseplease")) {

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
                }

                return false;
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
    }

    private static byte[] decodeB64(String base64String) {
        return Base64.getDecoder().decode(base64String);
    }
}
