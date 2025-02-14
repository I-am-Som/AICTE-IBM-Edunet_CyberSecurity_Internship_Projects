package com.Internship.steganography.service;

import org.opencv.core.Mat;
import org.opencv.core.MatOfByte;
import org.opencv.imgcodecs.Imgcodecs;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.logging.Logger;

@Service
public class SteganographyService {

    private static final Logger logger = Logger.getLogger(SteganographyService.class.getName());

    public File encodeMessage(MultipartFile imageFile, String message, String password) throws IOException {
        // Convert MultipartFile to byte array
        byte[] imageBytes = imageFile.getBytes();
        MatOfByte matOfByte = new MatOfByte(imageBytes);
        Mat image = Imgcodecs.imdecode(matOfByte, Imgcodecs.IMREAD_UNCHANGED);

        // Check if the image was successfully decoded
        if (image.empty()) {
            throw new IOException("Could not decode image. Ensure the image format is supported and the file is not corrupted.");
        }

        // Encrypt the message using the password
        String encryptedMessage = encryptMessage(message, password);

        // Check if the message can fit in the image
        if (!canEmbedMessage(image, encryptedMessage)) {
            throw new IOException("Message is too large to embed in this image.");
        }

        // Hide the encrypted message in the image
        hideMessageInImage(image, encryptedMessage);

        // Determine the file extension (default to PNG if not specified)
        String originalFileName = imageFile.getOriginalFilename();
        String fileExtension = getFileExtension(originalFileName);

        // Save the steganographed image to a temporary file
        File outputFile = File.createTempFile("steganographed", "." + fileExtension);
        boolean success = Imgcodecs.imwrite(outputFile.getAbsolutePath(), image);

        if (!success) {
            throw new IOException("Failed to save the steganographed image to disk.");
        }

        logger.info("Steganographed image saved to: " + outputFile.getAbsolutePath());
        return outputFile;
    }

    public String decodeMessage(MultipartFile imageFile, String password) throws IOException {
        // Convert MultipartFile to byte array
        byte[] imageBytes = imageFile.getBytes();
        MatOfByte matOfByte = new MatOfByte(imageBytes);
        Mat image = Imgcodecs.imdecode(matOfByte, Imgcodecs.IMREAD_UNCHANGED);

        // Check if the image was successfully decoded
        if (image.empty()) {
            throw new IOException("Could not decode image. Ensure the image format is supported and the file is not corrupted.");
        }

        // Extract the hidden message from the image
        String encryptedMessage = extractMessageFromImage(image);

        // Decrypt the message using the password
        return decryptMessage(encryptedMessage, password);
    }

    private String encryptMessage(String message, String password) {
        if (password.isEmpty()) {
            throw new IllegalArgumentException("Password cannot be empty.");
        }

        StringBuilder encrypted = new StringBuilder();
        int passLen = password.length();

        // XOR encryption
        for (int i = 0; i < message.length(); i++) {
            encrypted.append((char) (message.charAt(i) ^ password.charAt(i % passLen)));
        }

        return encrypted.toString();
    }

    private String decryptMessage(String encryptedMessage, String password) {
        // XOR decryption (same as encryption)
        return encryptMessage(encryptedMessage, password);
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
                int pixelValue = (int) pixel[channel];
                pixelValue = (pixelValue & 0xFE) | ((lengthByte >> j) & 1); // Set LSB
                pixel[channel] = (double) pixelValue;
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
                pixelValue = (pixelValue & 0xFE) | ((b >> j) & 1); // Set LSB
                pixel[channel] = (double) pixelValue;
                image.put(row, col, pixel);
                index++;
            }
        }

        logger.info("Message successfully embedded in the image.");
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
                lengthByte |= (((int) pixel[channel] & 1) << j); // Get LSB
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
                b |= (((int) pixel[channel] & 1) << j); // Get LSB
                index++;
            }
            messageBytes[i] = b;
        }

        logger.info("Message successfully extracted from the image.");
        return new String(messageBytes, StandardCharsets.UTF_8);
    }

    private boolean canEmbedMessage(Mat image, String message) {
        int availableBits = image.rows() * image.cols() * 3 * 8; // Total bits in the image
        int requiredBits = (message.length() + 4) * 8; // Message + 4 bytes for length
        return requiredBits <= availableBits;
    }

    private String getFileExtension(String fileName) {
        if (fileName == null || !fileName.contains(".")) {
            return "png"; // Default to PNG if no extension is found
        }
        return fileName.substring(fileName.lastIndexOf(".") + 1);
    }
}