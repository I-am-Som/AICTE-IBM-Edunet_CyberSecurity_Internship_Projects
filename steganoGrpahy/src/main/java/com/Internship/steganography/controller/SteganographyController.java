package com.Internship.steganography.controller;

import com.Internship.steganography.service.SteganographyService;
import org.springframework.core.io.FileSystemResource;
import org.springframework.core.io.Resource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.File;
import java.io.IOException;

@RestController
@RequestMapping("/steganography")
public class SteganographyController {

    private final SteganographyService steganographyService;

    public SteganographyController(SteganographyService steganographyService) {
        this.steganographyService = steganographyService;
    }

    @PostMapping("/encode")
    public ResponseEntity<Resource> encodeMessage(
            @RequestParam("image") MultipartFile imageFile,
            @RequestParam("message") String message,
            @RequestParam("password") String password) throws IOException {

        // Validate input
        if (imageFile.isEmpty()) {
            throw new IllegalArgumentException("Image file cannot be empty");
        }
        if (message == null || message.trim().isEmpty()) {
            throw new IllegalArgumentException("Message cannot be empty");
        }
        if (password == null || password.trim().isEmpty()) {
            throw new IllegalArgumentException("Password cannot be empty");
        }

        // Encode the message into the image
        File encodedImage = steganographyService.encodeMessage(imageFile, message, password);
        Resource resource = new FileSystemResource(encodedImage);

        ResponseEntity<Resource> response = ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=" + encodedImage.getName())
                .contentType(MediaType.IMAGE_PNG)
                .body(resource);

        // Schedule file deletion after response
        encodedImage.deleteOnExit();

        return response;
    }

    @PostMapping("/decode")
    public ResponseEntity<String> decodeMessage(
            @RequestParam("image") MultipartFile imageFile,
            @RequestParam("password") String password) throws IOException {

        // Validate input
        if (imageFile.isEmpty()) {
            throw new IllegalArgumentException("Image file cannot be empty");
        }
        if (password == null || password.trim().isEmpty()) {
            throw new IllegalArgumentException("Password cannot be empty");
        }

        // Decode the message from the image
        String decodedMessage = steganographyService.decodeMessage(imageFile, password);

        // Return the decoded message
        return ResponseEntity.ok(decodedMessage);
    }

    // Exception handler for IllegalArgumentException
    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<String> handleIllegalArgumentException(IllegalArgumentException ex) {
        return ResponseEntity.badRequest().body(ex.getMessage());
    }

    // Exception handler for IOException
    @ExceptionHandler(IOException.class)
    public ResponseEntity<String> handleIOException(IOException ex) {
        return ResponseEntity.internalServerError().body("An error occurred while processing the image: " + ex.getMessage());
    }

    // General exception handler
    @ExceptionHandler(Exception.class)
    public ResponseEntity<String> handleGeneralException(Exception ex) {
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Unexpected error: " + ex.getMessage());
    }
}
