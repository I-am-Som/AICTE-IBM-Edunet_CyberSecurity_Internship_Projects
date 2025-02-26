import React, { useState } from "react";

const EncodeComponent = () => {
  const [image, setImage] = useState(null);
  const [password, setPassword] = useState("");
  const [message, setMessage] = useState("");
  const [stegoImage, setStegoImage] = useState(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  const handleImageChange = (e) => {
    setImage(e.target.files[0]);
  };

  const handleEncode = async () => {
    if (!image || !password || !message) {
      setError("All fields are required!");
      return;
    }
    setError("");
    setLoading(true);

    const formData = new FormData();
    formData.append("image", image);
    formData.append("password", password);
    formData.append("message", message);

    try {
      const response = await fetch("http://localhost:8080/steganography/encode", {
        method: "POST",
        body: formData,
      });

      if (!response.ok) {
        throw new Error("Encoding failed!");
      }

      const blob = await response.blob();
      setStegoImage(URL.createObjectURL(blob));
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="flex flex-col space-y-4">
      <input type="file" accept="image/*" onChange={handleImageChange} className="p-2 bg-gray-700 rounded" />
      <input type="password" placeholder="Password" value={password} onChange={(e) => setPassword(e.target.value)} className="p-2 bg-gray-700 rounded" />
      <textarea placeholder="Message to encode" value={message} onChange={(e) => setMessage(e.target.value)} className="p-2 bg-gray-700 rounded"></textarea>
      <button onClick={handleEncode} className="p-2 bg-blue-500 rounded" disabled={loading}>
        {loading ? "Encoding..." : "Encode"}
      </button>
      {error && <p className="text-red-400">{error}</p>}
      {stegoImage && (
        <div>
          <p>Stego Image:</p>
          <img src={stegoImage} alt="Steganographed" className="w-full rounded" />
          <a href={stegoImage} download="stego-image.png" className="block mt-2 text-blue-400 underline">Download Image</a>
        </div>
      )}
    </div>
  );
};

export default EncodeComponent;
