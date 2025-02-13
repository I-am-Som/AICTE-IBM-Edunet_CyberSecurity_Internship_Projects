import React, { useState, useEffect } from "react";
import EncodeComponent from "./components/EncodeComponent";
import DecodeComponent from "./components/DecodeComponent";

const SteganographyTool = () => {
  const [activeTab, setActiveTab] = useState(() => {
    return localStorage.getItem("activeTab") || "encode";
  });

  useEffect(() => {
    localStorage.setItem("activeTab", activeTab);
  }, [activeTab]);

  const renderActiveComponent = () => {
    return activeTab === "encode" ? <EncodeComponent /> : <DecodeComponent />;
  };

  return (
    <div className="min-h-screen bg-gray-900 text-white flex flex-col items-center p-5">
      {/* Navigation Tabs */}
      <nav className="flex space-x-4 bg-gray-800 p-3 rounded-lg shadow-md w-full max-w-md mb-5">
        {["encode", "decode"].map((tab) => (
          <button
            key={tab}
            className={`flex-1 py-2 text-center rounded-lg transition-all duration-300 ${
              activeTab === tab ? "bg-blue-500" : "bg-gray-700 hover:bg-gray-600"
            }`}
            onClick={() => setActiveTab(tab)}
          >
            {tab === "encode" ? "Encoder" : "Decoder"}
          </button>
        ))}
      </nav>

      {/* Content Section */}
      <div className="bg-gray-800 p-6 rounded-lg shadow-lg w-full max-w-md">
        {renderActiveComponent()}
      </div>
    </div>
  );
};

export default SteganographyTool;
