/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package Utilities;

import java.io.BufferedReader;
import java.io.File;
import java.io.InputStreamReader;
import javax.json.Json;
import javax.json.JsonObjectBuilder;

/**
 *
 * @author azizmma
 */
public class Utils {

    public static String executeConsoleCommand(String command,File fl) {

        StringBuffer output = new StringBuffer();

        Process p;
        try {
            p = Runtime.getRuntime().exec(command,null,fl );
//            p.waitFor();
            BufferedReader reader = new BufferedReader(new InputStreamReader(p.getInputStream()));

            String line = "";
            while ((line = reader.readLine()) != null) {
                output.append(line + "\n");
            }

        } catch (Exception e) {
            e.printStackTrace();
        }

        return output.toString();   

    }

    public static String getMessage(String type, JsonObjectBuilder message) {
        return Json.createObjectBuilder()
                .add("type", type)
                .add("msg", message.build())
                .build()
                .toString();
    }

    public static String getMessage(String type, Integer message) {
        return Json.createObjectBuilder()
                .add("type", type)
                .add("msg", message)
                .build()
                .toString();
    }

    public static String getMessage(String type, String message) {
        return Json.createObjectBuilder()
                .add("type", type)
                .add("msg", message)
                .build()
                .toString();             
    }
}
