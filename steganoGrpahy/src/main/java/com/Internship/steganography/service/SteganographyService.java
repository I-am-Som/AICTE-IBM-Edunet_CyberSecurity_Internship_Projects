package com.Internship.steganography.service;

import org.opencv.core.CvType;
import org.opencv.core.Mat;
import org.opencv.core.MatOfByte;
import org.opencv.imgcodecs.Imgcodecs;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

@Service
public class SteganographyService {

    public File encodeMessage(MultipartFile imageFile, String message, String password) throws IOException {
        // Convert MultipartFile to byte array
        byte[] imageBytes = imageFile.getBytes();
        MatOfByte matOfByte = new MatOfByte(imageBytes);
        Mat image = Imgcodecs.imdecode(matOfByte, Imgcodecs.IMREAD_UNCHANGED);

        if (image.empty()) {
            throw new IOException("Could not decode image");
        }

        // Encrypt message using password (Simple XOR for now)
        String encryptedMessage = encryptMessage(message, password);

        // Ensure message fits within the image
        if (!canEmbedMessage(image, encryptedMessage)) {
            throw new IOException("Message is too large for this image.");
        }

        // Hide the message in the image (LSB technique)
        hideMessageInImage(image, encryptedMessage);

        // Save the steganographed image
        File outputFile = File.createTempFile("steganographed", ".png");
        Imgcodecs.imwrite(outputFile.getAbsolutePath(), image);

        return outputFile;
    }

    public String decodeMessage(MultipartFile imageFile, String password) throws IOException {
        // Convert MultipartFile to byte array
        byte[] imageBytes = imageFile.getBytes();
        MatOfByte matOfByte = new MatOfByte(imageBytes);
        Mat image = Imgcodecs.imdecode(matOfByte, Imgcodecs.IMREAD_UNCHANGED);

        if (image.empty()) {
            throw new IOException("Could not decode image");
        }

        // Extract the hidden message from the image
        String encryptedMessage = extractMessageFromImage(image);

        // Decrypt the message using password
        return decryptMessage(encryptedMessage, password);
    }

    private String encryptMessage(String message, String password) {
        if (password.isEmpty()) {
            throw new IllegalArgumentException("Password cannot be empty");
        }

        StringBuilder encrypted = new StringBuilder();
        int passLen = password.length();
        for (int i = 0; i < message.length(); i++) {
            encrypted.append((char) (message.charAt(i) ^ password.charAt(i % passLen)));
        }
        return encrypted.toString();
    }

    private String decryptMessage(String encryptedMessage, String password) {
        return encryptMessage(encryptedMessage, password); // XOR again to decrypt
    }

    private void hideMessageInImage(Mat image, String message) {
        byte[] messageBytes = message.getBytes(StandardCharsets.UTF_8);
        int messageLength = messageBytes.length;
        int index = 0;

        // Embed the message length in the first 32 bits (4 bytes)
        for (int i = 0; i < 4; i++) {
            int lengthByte = (messageLength >> (8 * i)) & 0xFF;
            for (int j = 0; j < 8; j++) {
                int row = index / (image.cols() * 3);
                int col = (index % (image.cols() * 3)) / 3;
                int channel = (index % (image.cols() * 3)) % 3;

                double[] pixel = image.get(row, col);
                int pixelValue = (int) pixel[channel]; // Cast to int for bitwise operations
                pixelValue = (pixelValue & 0xFE) | ((lengthByte >> j) & 1); // Modify the LSB
                pixel[channel] = (double) pixelValue; // Convert back to double
                image.put(row, col, pixel);
                index++;
            }
        }

        // Embed the message
        for (byte b : messageBytes) {
            for (int j = 0; j < 8; j++) {
                int row = index / (image.cols() * 3);
                int col = (index % (image.cols() * 3)) / 3;
                int channel = (index % (image.cols() * 3)) % 3;

                double[] pixel = image.get(row, col);
                int pixelValue = (int) pixel[channel];
                pixelValue = (pixelValue & 0xFE) | ((b >> j) & 1);
                pixel[channel] = (double) pixelValue;
                image.put(row, col, pixel);
                index++;
            }
        }
    }

    private String extractMessageFromImage(Mat image) {
        int index = 0;
        int messageLength = 0;

        // Extract the message length from the first 32 bits (4 bytes)
        for (int i = 0; i < 4; i++) {
            int lengthByte = 0;
            for (int j = 0; j < 8; j++) {
                int row = index / (image.cols() * 3);
                int col = (index % (image.cols() * 3)) / 3;
                int channel = (index % (image.cols() * 3)) % 3;

                double[] pixel = image.get(row, col);
                lengthByte |= (((int) pixel[channel] & 1) << j);
                index++;
            }
            messageLength |= (lengthByte & 0xFF) << (8 * i);
        }

        // Extract the message
        byte[] messageBytes = new byte[messageLength];
        for (int i = 0; i < messageLength; i++) {
            byte b = 0;
            for (int j = 0; j < 8; j++) {
                int row = index / (image.cols() * 3);
                int col = (index % (image.cols() * 3)) / 3;
                int channel = (index % (image.cols() * 3)) % 3;

                double[] pixel = image.get(row, col);
                b |= (((int) pixel[channel] & 1) << j);
                index++;
            }
            messageBytes[i] = b;
        }

        return new String(messageBytes, StandardCharsets.UTF_8);
    }

    private boolean canEmbedMessage(Mat image, String message) {
        int availableBits = image.rows() * image.cols() * 3 * 8; // Each pixel has 3 channels
        int requiredBits = (message.length() + 4) * 8; // Message + 4 bytes for length
        return requiredBits <= availableBits;
    }
}
