package com.xinsane.simple_encrypt.test;

import org.junit.runner.JUnitCore;
import org.junit.runner.Result;
import org.junit.runner.notification.Failure;

public class TestAll {
    public static void main(String[] args) {
        Result res1 = JUnitCore.runClasses(SimpleStringTest.class);
        System.out.println();
        Result res2 = JUnitCore.runClasses(AvalancheEffectTest.class);
        System.out.println();
        for (Failure failure : res1.getFailures())
            System.err.println(failure.toString());
        for (Failure failure : res2.getFailures())
            System.err.println(failure.toString());
        if (res1.wasSuccessful() && res2.wasSuccessful())
            System.out.println("All tests okay.");
    }
}
