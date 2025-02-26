package com.Internship.steganography;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class SteganographyApplication {

	static {
		try {
			String opencvPath = System.getProperty("user.dir") + "/src/main/resources/libs/opencv_java490.dll";
			System.load(opencvPath);
			System.out.println("✅ OpenCV loaded successfully from: " + opencvPath);
		} catch (UnsatisfiedLinkError e) {
			System.err.println("❌ Failed to load OpenCV: " + e.getMessage());
		}
	}


	public static void main(String[] args) {
		SpringApplication.run(SteganographyApplication.class, args);
	}

}