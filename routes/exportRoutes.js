import express from "express";
import PDFDocument from "pdfkit";

const router = express.Router();

router.post("/pdf", async (req, res) => {
  try {
    const { roomCode, messages, includeMedia = false } = req.body;

    if (!roomCode || !messages) {
      return res
        .status(400)
        .json({ msg: "Room code and messages are required" });
    }

    const doc = new PDFDocument();
    res.setHeader("Content-Type", "application/pdf");
    res.setHeader(
      "Content-Disposition",
      `attachment; filename=chat-${roomCode}.pdf`
    );

    doc.pipe(res);

    // Header
    doc.fontSize(20).text(`Chat Room: ${roomCode}`, { align: "center" });
    doc.moveDown();
    doc
      .fontSize(12)
      .text(`Exported on: ${new Date().toLocaleString()}`, { align: "center" });
    doc.moveDown();
    doc.moveDown();

    // Messages
    let yPosition = doc.y;
    const pageWidth = 500;
    const leftMargin = 50;

    messages.forEach((message, index) => {
      // Check if we need a new page
      if (yPosition > 700) {
        doc.addPage();
        yPosition = 50;
      }

      if (message.type === "system") {
        doc.fillColor("gray").fontSize(10);
        const systemText = `⚡ ${message.content}`;
        const textWidth = doc.widthOfString(systemText);
        doc.text(
          systemText,
          (pageWidth - textWidth) / 2 + leftMargin,
          yPosition
        );
        yPosition += 20;
      } else {
        doc.fillColor("black").fontSize(10);

        // Username and time
        const headerText = `${message.username} • ${new Date(
          message.timestamp
        ).toLocaleString()}`;
        doc.text(headerText, leftMargin, yPosition);
        yPosition += 15;

        // Message content
        doc.fontSize(12);
        if (message.type === "file") {
          const fileText = `📎 File: ${message.fileName || "Unknown file"}`;
          doc.text(fileText, leftMargin, yPosition);
          yPosition += 20;

          if (includeMedia && message.fileUrl) {
            doc.fontSize(10).fillColor("blue");
            doc.text(`URL: ${message.fileUrl}`, leftMargin, yPosition, {
              width: pageWidth,
              link: message.fileUrl,
            });
            yPosition += 15;
            doc.fillColor("black");
          }
        } else {
          doc.text(message.content, leftMargin, yPosition, {
            width: pageWidth,
          });
          yPosition +=
            doc.heightOfString(message.content, { width: pageWidth }) + 10;
        }
      }

      // Separator line
      doc
        .moveTo(leftMargin, yPosition)
        .lineTo(leftMargin + pageWidth, yPosition)
        .strokeColor("#cccccc")
        .stroke();
      yPosition += 20;
    });

    doc.end();
  } catch (error) {
    console.error("PDF export error:", error);
    res.status(500).json({ msg: "Failed to generate PDF" });
  }
});

export default router;
