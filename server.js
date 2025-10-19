import express from "express";
import { createServer } from "http";
import { Server } from "socket.io";
import cors from "cors";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import validator from "validator";
import AWS from "aws-sdk"; // Added AWS SDK
import connectDB from "./config/db.js";

import dotenv from "dotenv"; // Add dotenv import

// Initialize dotenv to load .env file
dotenv.config();

const app = express();

// AWS S3 Configuration
const s3 = new AWS.S3({
  accessKeyId: process.env.AWS_ACCESS_KEY_ID,
  secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
  region: process.env.AWS_REGION || "ap-south-1",
});

// Connect to MongoDB
connectDB();

// Security middleware
app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        styleSrc: ["'self'", "'unsafe-inline'"],
        scriptSrc: ["'self'"],
        connectSrc: [
          "'self'",
          "ws:",
          "wss:",
          process.env.CLIENT_URL || "http://localhost:5173",
          `https://${process.env.AWS_S3_BUCKET}.s3.${process.env.AWS_REGION}.amazonaws.com`, // Allow S3
        ],
      },
    },
  })
);

// CORS configuration
app.use(
  cors({
    origin: (origin, callback) => {
      const allowedOrigins = [
        process.env.CLIENT_URL || "http://localhost:5173",
        "https://private-frontend-kov9nbd7m-bodapati-sai-praneeths-projects.vercel.app", // your frontend Render URL
        "https://securechat1335.vercel.app",
        "https://private-backend-k0py.onrender.com", // backend itself
      ];
      if (!origin || allowedOrigins.includes(origin)) {
        callback(null, true);
      } else {
        callback(new Error("Not allowed by CORS"));
      }
    },
    credentials: true,
  })
);

// Rate limiting
const limiter = rateLimit({
  windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS) || 15 * 60 * 1000, // 15 minutes
  max: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS) || 100,
});
app.use(limiter);

app.use(express.json({ limit: "10kb" }));

// Health check endpoint
app.get("/health", (req, res) => {
  res.json({
    status: "OK",
    timestamp: new Date().toISOString(),
    serverIP: req.headers["x-forwarded-for"] || req.socket.remoteAddress,
    port: process.env.PORT || 5000,
  });
});

// Server info endpoint
app.get("/info", (req, res) => {
  res.json({
    server: "Secure Chat Server",
    version: "1.0.0",
    ip: req.headers["x-forwarded-for"] || req.socket.remoteAddress,
    port: process.env.PORT || 5000,
  });
});

const server = createServer(app);

const io = new Server(server, {
  cors: {
    origin: (origin, callback) => {
      const allowedOrigins = [
        process.env.CLIENT_URL || "http://localhost:5173",
        "https://private-frontend-kov9nbd7m-bodapati-sai-praneeths-projects.vercel.app",
        "https://securechat1335.vercel.app",
        "https://private-backend-k0py.onrender.com",
      ];
      if (!origin || allowedOrigins.includes(origin)) {
        callback(null, true);
      } else {
        callback(new Error("Not allowed by CORS"));
      }
    },
    methods: ["GET", "POST"],
    credentials: true,
  },
});

// In-memory storage for rooms
const rooms = new Map();
const userSessions = new Map();
const messageRateLimits = new Map();
const roomFiles = new Map(); // Track files per room: Map<key, uploaderSocketId>

const sanitize = {
  username: (input) => {
    const sanitized = validator.escape(validator.trim(input));
    return sanitized && sanitized.length <= 20 ? sanitized : null;
  },
  roomCode: (input) => {
    const sanitized = validator.escape(validator.trim(input));
    return sanitized && sanitized.length <= 20 ? sanitized : null;
  },
  message: (input) => {
    const sanitized = validator.escape(validator.trim(input));
    return sanitized && sanitized.length <= 1000 ? sanitized : null;
  },
  filename: (input) => {
    const sanitized = validator.escape(input).replace(/[^a-zA-Z0-9.-]/g, "_");
    return sanitized && sanitized.length <= 100 ? sanitized : null;
  },
};

const checkRateLimit = (socketId) => {
  const now = Date.now();
  const windowMs = parseInt(process.env.RATE_LIMIT_WINDOW_MS) || 15 * 60 * 1000;
  const maxMessages = parseInt(process.env.RATE_LIMIT_MAX_REQUESTS) || 100;

  if (!messageRateLimits.has(socketId)) {
    messageRateLimits.set(socketId, []);
  }

  const timestamps = messageRateLimits.get(socketId);
  timestamps.push(now);
  messageRateLimits.set(
    socketId,
    timestamps.filter((ts) => now - ts < windowMs)
  );

  return timestamps.length <= maxMessages;
};

io.on("connection", (socket) => {
  console.log("✅ New connection:", socket.id);

  let currentRoom = null;
  let currentUsername = null;

  socket.on("joinRoom", ({ username, roomCode }) => {
    try {
      const sanitizedUsername = sanitize.username(username);
      const sanitizedRoomCode = sanitize.roomCode(roomCode);

      if (!sanitizedUsername || !sanitizedRoomCode) {
        socket.emit("error", "Invalid username or room code");
        return;
      }

      if (userSessions.has(socket.id)) {
        socket.emit("error", "Already in a room");
        return;
      }

      if (!rooms.has(sanitizedRoomCode)) {
        rooms.set(sanitizedRoomCode, {
          users: new Map(),
          messages: [],
          lastActivity: Date.now(),
        });
        roomFiles.set(sanitizedRoomCode, new Map()); // Map<key, uploaderSocketId>
      }

      const room = rooms.get(sanitizedRoomCode);
      if (room.users.size >= 50) {
        socket.emit("error", "Room is full (max 50 users)");
        return;
      }

      room.users.set(socket.id, sanitizedUsername);
      userSessions.set(socket.id, {
        username: sanitizedUsername,
        roomCode: sanitizedRoomCode,
      });

      currentRoom = sanitizedRoomCode;
      currentUsername = sanitizedUsername;

      socket.join(sanitizedRoomCode);

      socket.emit("loadMessages", room.messages);
      io.to(sanitizedRoomCode).emit(
        "roomUsers",
        Array.from(room.users.values())
      );

      const systemMessage = {
        id: Date.now().toString(),
        type: "system",
        content: `${sanitizedUsername} joined the room`,
        timestamp: new Date().toISOString(),
      };

      room.messages.push(systemMessage);
      io.to(sanitizedRoomCode).emit("systemMessage", systemMessage);

      console.log(`👤 ${sanitizedUsername} joined room ${sanitizedRoomCode}`);
    } catch (error) {
      console.error("Join room error:", error);
      socket.emit("error", "Failed to join room");
    }
  });

  socket.on("requestUploadUrl", ({ filename, fileType }) => {
    if (!currentRoom || !currentUsername) {
      socket.emit("error", "Not in a room");
      return;
    }

    const sanitizedFilename = sanitize.filename(filename);
    if (!sanitizedFilename) {
      socket.emit("error", "Invalid filename");
      return;
    }

    const key = `rooms/${currentRoom}/${Date.now()}-${sanitizedFilename}`;
    const params = {
      Bucket: process.env.AWS_S3_BUCKET,
      Key: key,
      ContentType: fileType || "application/octet-stream",
      Expires: 3600,
      ACL: "private",
    };

    try {
      const presignedUrl = s3.getSignedUrl("putObject", params);
      const fileUrl = `https://${process.env.AWS_S3_BUCKET}.s3.${process.env.AWS_REGION}.amazonaws.com/${key}`;

      roomFiles.get(currentRoom).set(key, socket.id);

      socket.emit("uploadUrl", { presignedUrl, fileUrl, key });
      console.log(
        `📤 Presigned URL generated for ${sanitizedFilename} in room ${currentRoom}`
      );
    } catch (error) {
      console.error("Presigned URL error:", error);
      socket.emit("error", "Failed to generate upload URL");
    }
  });

  socket.on("fileUploaded", ({ fileUrl, filename, key }) => {
    if (!currentRoom || !currentUsername) {
      socket.emit("error", "Not in a room");
      return;
    }

    const message = {
      id: Date.now().toString(),
      username: currentUsername,
      content: `📎 ${filename} (${fileUrl})`,
      timestamp: new Date().toISOString(),
      type: "file",
      fileKey: key,
      uploaderSocketId: socket.id,
    };

    const room = rooms.get(currentRoom);
    if (room) {
      room.messages.push(message);
      io.to(currentRoom).emit("message", message);
    }
  });

  socket.on("requestDownloadUrl", ({ key }) => {
    if (!currentRoom || !currentUsername) {
      socket.emit("error", "Not in a room");
      return;
    }

    const params = {
      Bucket: process.env.AWS_S3_BUCKET,
      Key: key,
      Expires: 3600,
    };

    try {
      const downloadUrl = s3.getSignedUrl("getObject", params);
      socket.emit("downloadUrl", { key, downloadUrl });
      console.log(`📥 Presigned download URL generated for ${key}`);
    } catch (error) {
      console.error("Download URL error:", error);
      socket.emit("error", "Failed to generate download URL");
    }
  });

  socket.on("deleteFile", ({ key }) => {
    if (!currentRoom || !currentUsername) {
      socket.emit("error", "Not in a room");
      return;
    }

    const fileMap = roomFiles.get(currentRoom);
    if (!fileMap.has(key) || fileMap.get(key) !== socket.id) {
      socket.emit("error", "Not authorized to delete this file");
      return;
    }

    const params = {
      Bucket: process.env.AWS_S3_BUCKET,
      Key: key,
    };

    s3.deleteObject(params, (err) => {
      if (err) {
        console.error(`File deletion error: ${key}`, err);
        socket.emit("error", "Failed to delete file");
        return;
      }
      fileMap.delete(key);
      const systemMessage = {
        id: Date.now().toString(),
        type: "system",
        content: `${currentUsername} deleted a file`,
        timestamp: new Date().toISOString(),
      };
      const room = rooms.get(currentRoom);
      room.messages.push(systemMessage);
      io.to(currentRoom).emit("systemMessage", systemMessage);
      io.to(currentRoom).emit("fileDeleted", { key });
      console.log(`🗑️ File deleted: ${key} by ${currentUsername}`);
    });
  });

  socket.on("sendMessage", (messageContent) => {
    try {
      if (!currentRoom || !currentUsername) {
        socket.emit("error", "Not in a room");
        return;
      }

      if (!checkRateLimit(socket.id)) {
        socket.emit("error", "Message rate limit exceeded");
        return;
      }

      const sanitizedMessage = sanitize.message(messageContent);
      if (!sanitizedMessage) {
        socket.emit("error", "Invalid message");
        return;
      }

      const room = rooms.get(currentRoom);
      if (!room || !room.users.has(socket.id)) {
        socket.emit("error", "Not authorized");
        return;
      }

      const message = {
        id: Date.now().toString(),
        username: currentUsername,
        content: sanitizedMessage,
        timestamp: new Date().toISOString(),
        type: "user",
      };

      room.messages.push(message);
      room.lastActivity = Date.now();

      io.to(currentRoom).emit("message", message);
    } catch (error) {
      console.error("Send message error:", error);
      socket.emit("error", "Failed to send message");
    }
  });

  socket.on("typingStart", () => {
    if (currentRoom && currentUsername) {
      socket.to(currentRoom).emit("userTyping", currentUsername);
    }
  });

  socket.on("typingStop", () => {
    if (currentRoom) {
      socket.to(currentRoom).emit("userStoppedTyping", currentUsername);
    }
  });

  socket.on("disconnect", (reason) => {
    console.log("❌ User disconnected:", socket.id, "Reason:", reason);

    if (currentRoom && currentUsername) {
      const room = rooms.get(currentRoom);
      if (room) {
        room.users.delete(socket.id);

        const systemMessage = {
          id: Date.now().toString(),
          type: "system",
          content: `${currentUsername} left the room`,
          timestamp: new Date().toISOString(),
        };

        room.messages.push(systemMessage);
        io.to(currentRoom).emit("systemMessage", systemMessage);
        io.to(currentRoom).emit("roomUsers", Array.from(room.users.values()));

        console.log(
          `👋 ${currentUsername} left room ${currentRoom}. Remaining users: ${room.users.size}`
        );

        if (room.users.size === 0) {
          const files = roomFiles.get(currentRoom);
          if (files && files.size > 0) {
            files.forEach((uploaderId, key) => {
              s3.deleteObject(
                { Bucket: process.env.AWS_S3_BUCKET, Key: key },
                (err) => {
                  if (err) console.error(`File deletion error: ${key}`, err);
                  else console.log(`🗑️ Deleted file: ${key}`);
                }
              );
            });
            roomFiles.delete(currentRoom);
          }
          rooms.delete(currentRoom);
          console.log(`🧹 Room ${currentRoom} deleted (no users)`);
        }
      }
    }

    userSessions.delete(socket.id);
    messageRateLimits.delete(socket.id);
  });
});

const PORT = process.env.PORT || 5000;
server.listen(PORT, () => console.log(`Server running on ${PORT}`));

// Handle graceful shutdown
process.on("SIGINT", () => {
  console.log("\n🛑 Shutting down server gracefully...");
  server.close(() => {
    console.log("✅ Server closed");
    process.exit(0);
  });
});
