package org.tool.passfort.util.qr;

import com.google.zxing.BarcodeFormat;
import com.google.zxing.EncodeHintType;
import com.google.zxing.WriterException;
import com.google.zxing.common.BitMatrix;
import com.google.zxing.qrcode.QRCodeWriter;
import com.google.zxing.qrcode.decoder.ErrorCorrectionLevel;

import java.awt.*;
import java.awt.image.BufferedImage;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import javax.imageio.ImageIO;

public class QRCodeUtil {

    /**
     * 生成二维码并返回Base64字符串
     *
     * @param text              要编码的文本
     * @param width             二维码宽度（常见值：200，单位：像素）
     * @param height            二维码高度（常见值：200，单位：像素）
     * @param imageFormat       图片格式（如PNG、JPEG）, 例如 "PNG"
     * @param foregroundColor   二维码颜色，例如Color.BLACK
     * @param backgroundColor   背景颜色, 例如Color.WHITE
     * @param errorCorrection   错误校正级别（L、M、Q、H）, 例如ErrorCorrectionLevel.H
     * @param margin            边框大小（常见值：2、4)
     * @return Base64格式的二维码图片
     * @throws WriterException  如果二维码生成失败
     * @throws IOException      如果图片处理失败
     */
    public static String generateQRCode(
            String text,
            int width,
            int height,
            String imageFormat,
            Color foregroundColor,
            Color backgroundColor,
            ErrorCorrectionLevel errorCorrection,
            int margin
    ) throws WriterException, IOException {
        // 设置二维码参数
        Map<EncodeHintType, Object> hints = new HashMap<>();
        hints.put(EncodeHintType.CHARACTER_SET, "UTF-8");
        hints.put(EncodeHintType.ERROR_CORRECTION, errorCorrection);
        hints.put(EncodeHintType.MARGIN, margin);

        // 创建QRCodeWriter对象
        QRCodeWriter qrCodeWriter = new QRCodeWriter();
        BitMatrix bitMatrix = qrCodeWriter.encode(text, BarcodeFormat.QR_CODE, width, height, hints);

        // 创建图片
        BufferedImage bufferedImage = new BufferedImage(width, height, BufferedImage.TYPE_INT_RGB);
        bufferedImage.createGraphics();

        Graphics2D graphics = (Graphics2D) bufferedImage.getGraphics();
        graphics.setColor(backgroundColor);
        graphics.fillRect(0, 0, width, height);

        graphics.setColor(foregroundColor);
        for (int i = 0; i < width; i++) {
            for (int j = 0; j < height; j++) {
                if (bitMatrix.get(i, j)) {
                    graphics.fillRect(i, j, 1, 1);
                }
            }
        }

        // 将图片转换为Base64格式
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        ImageIO.write(bufferedImage, imageFormat, byteArrayOutputStream);
        byte[] imageBytes = byteArrayOutputStream.toByteArray();

        return java.util.Base64.getEncoder().encodeToString(imageBytes);
    }

    public static void main(String[] args) {
        try {
            String text = "Hello, World!";
            int width = 200;
            int height = 200;
            String imageFormat = "PNG";
            Color foregroundColor = Color.BLACK;
            Color backgroundColor = Color.WHITE;
            ErrorCorrectionLevel errorCorrection = ErrorCorrectionLevel.H;
            int margin = 2;

            String base64Image = QRCodeUtil.generateQRCode(
                    text,
                    width,
                    height,
                    imageFormat,
                    foregroundColor,
                    backgroundColor,
                    errorCorrection,
                    margin
            );

            System.out.println("Base64 Image: " + base64Image);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
