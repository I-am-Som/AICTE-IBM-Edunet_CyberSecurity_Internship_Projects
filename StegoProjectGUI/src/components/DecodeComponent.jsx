import React, { useState } from "react";

const DecodeComponent = () => {
  const [stegoImage, setStegoImage] = useState(null);
  const [password, setPassword] = useState("");
  const [decodedMessage, setDecodedMessage] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  const handleImageChange = (e) => {
    const file = e.target.files[0];
    if (file && file.type.startsWith("image/")) {
      setStegoImage(file);
      setError(""); 
    } else {
      setError("Please upload a valid image file.");
      setStegoImage(null);
    }
  };

  const handleDecode = async () => {
    if (!stegoImage || !password) {
      setError("Image and password are required!");
      return;
    }

    if (password.length < 4) {
      setError("Password must be at least 4 characters long.");
      return;
    }

    setError("");
    setLoading(true);

    const formData = new FormData();
    formData.append("image", stegoImage);
    formData.append("password", password);

    try {
      const response = await fetch("http://localhost:8080/steganography/decode", {
        method: "POST",
        body: formData,
      });

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.message || "Decoding failed!");
      }

      const data = await response.text(); 
      setDecodedMessage(data);
    } catch (err) {
      setError(err.message || "An error occurred during decoding.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="flex flex-col space-y-4 max-w-md mx-auto p-4 bg-gray-800 rounded-lg shadow-lg">
      <h1 className="text-2xl font-bold text-white mb-4">Decode Message</h1>

      {/* File Input */}
      <input
        type="file"
        accept="image/*"
        onChange={handleImageChange}
        className="p-2 bg-gray-700 rounded text-white"
        disabled={loading}
      />

      {/* Password Input */}
      <input
        type="password"
        placeholder="Password"
        value={password}
        onChange={(e) => setPassword(e.target.value)}
        className="p-2 bg-gray-700 rounded text-white"
        disabled={loading}
      />

      {/* Decode Button */}
      <button
        onClick={handleDecode}
        className={`p-2 ${
          loading ? "bg-blue-300" : "bg-blue-500 hover:bg-blue-600"
        } rounded text-white`}
        disabled={loading}
      >
        {loading ? "Decoding..." : "Decode"}
      </button>

      {/* Error Message */}
      {error && <p className="text-red-400 text-sm">{error}</p>}

      {/* Decoded Message */}
      {decodedMessage && (
        <div className="mt-4 p-3 bg-gray-700 rounded">
          <p className="text-green-400 font-semibold">Decoded Message:</p>
          <p className="text-white break-words">{decodedMessage}</p>
        </div>
      )}
    </div>
  );
};

export default DecodeComponent;