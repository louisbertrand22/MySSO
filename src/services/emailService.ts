import nodemailer from 'nodemailer';
import { config } from '../config/env';

function createTransporter() {
  if (!config.smtp.host) return null;
  return nodemailer.createTransport({
    host: config.smtp.host,
    port: config.smtp.port,
    secure: config.smtp.port === 465,
    auth: { user: config.smtp.user, pass: config.smtp.pass },
    logger: false,
    debug: false,
  });
}

export class EmailService {
  static async sendEmailVerification(email: string, verifyUrl: string): Promise<void> {
    const transporter = createTransporter();

    const html = `
      <div style="font-family:sans-serif;max-width:480px;margin:0 auto">
        <h2 style="color:#4f46e5">Vérifiez votre adresse e-mail</h2>
        <p>Merci de vous être inscrit sur MySSO. Cliquez sur le bouton ci-dessous pour activer votre compte.</p>
        <p>Ce lien expire dans <strong>24 heures</strong>.</p>
        <a href="${verifyUrl}" style="display:inline-block;margin:16px 0;padding:12px 24px;background:#4f46e5;color:#fff;text-decoration:none;border-radius:8px;font-weight:600">
          Vérifier mon adresse e-mail
        </a>
        <p style="color:#6b7280;font-size:13px">Si vous n'avez pas créé de compte, ignorez cet e-mail.</p>
        <p style="color:#6b7280;font-size:12px">Lien: ${verifyUrl}</p>
      </div>
    `;

    if (!transporter) {
      console.log('\n[EMAIL — VERIFY EMAIL]');
      console.log(`To: ${email}`);
      console.log(`Verify URL: ${verifyUrl}\n`);
      return;
    }

    const info = await transporter.sendMail({
      from: config.smtp.from,
      to: email,
      subject: 'Vérifiez votre adresse e-mail MySSO',
      html,
    });
    console.log(`[EMAIL] Sent successfully. messageId=${info.messageId} response=${info.response}`);
  }

  static async sendPasswordReset(email: string, resetUrl: string): Promise<void> {
    const transporter = createTransporter();

    console.log(`[EMAIL] SMTP configured: ${!!config.smtp.host}, from: ${config.smtp.from}, to: ${email}`);

    const html = `
      <div style="font-family:sans-serif;max-width:480px;margin:0 auto">
        <h2 style="color:#4f46e5">Réinitialisation du mot de passe</h2>
        <p>Vous avez demandé une réinitialisation de votre mot de passe MySSO.</p>
        <p>Cliquez sur le bouton ci-dessous. Ce lien expire dans <strong>1 heure</strong> et ne peut être utilisé qu'une seule fois.</p>
        <a href="${resetUrl}" style="display:inline-block;margin:16px 0;padding:12px 24px;background:#4f46e5;color:#fff;text-decoration:none;border-radius:8px;font-weight:600">
          Réinitialiser mon mot de passe
        </a>
        <p style="color:#6b7280;font-size:13px">Si vous n'avez pas fait cette demande, ignorez cet e-mail. Votre mot de passe reste inchangé.</p>
        <p style="color:#6b7280;font-size:12px">Lien: ${resetUrl}</p>
      </div>
    `;

    if (!transporter) {
      // Dev fallback: log to console when SMTP is not configured
      console.log('\n[EMAIL — RESET PASSWORD]');
      console.log(`To: ${email}`);
      console.log(`Reset URL: ${resetUrl}\n`);
      return;
    }

    const info = await transporter.sendMail({
      from: config.smtp.from,
      to: email,
      subject: 'Réinitialisation de votre mot de passe MySSO',
      html,
    });
    console.log(`[EMAIL] Sent successfully. messageId=${info.messageId} response=${info.response}`);
  }
}
