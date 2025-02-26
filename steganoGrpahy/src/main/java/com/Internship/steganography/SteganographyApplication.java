package com.Internship.steganography;

import org.opencv.core.Core;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class SteganographyApplication {

	static {
		try {
			// Load OpenCV native library automatically
			System.loadLibrary(Core.NATIVE_LIBRARY_NAME);
			System.out.println("✅ OpenCV Loaded Successfully");
		} catch (UnsatisfiedLinkError e) {
			System.err.println("❌ Failed to load OpenCV: " + e.getMessage());
		}
	}

	public static void main(String[] args) {
		SpringApplication.run(SteganographyApplication.class, args);
	}
}
