export type EmailLabel = 0 | 1; // 1 = phishing, 0 = legitimate

export interface LabeledEmail {
  subject: string;
  body: string;
  label: EmailLabel;
  urlCount?: number;
  urgency?: number;
  credentialRequest?: number;
  financialRequest?: number;
}

function phish(
  subject: string,
  body: string,
  extras?: Partial<Omit<LabeledEmail, "subject" | "body" | "label">>
): LabeledEmail {
  return { subject, body, label: 1, ...extras };
}

function ham(
  subject: string,
  body: string,
  extras?: Partial<Omit<LabeledEmail, "subject" | "body" | "label">>
): LabeledEmail {
  return { subject, body, label: 0, ...extras };
}

/**
 * Compact public-style phishing vs legitimate corpus for the prototype
 * TF-IDF classifier. Examples are original short texts in the style of
 * well-known public spam/phishing patterns (not a dump of a copyrighted
 * mailbox). Split in trainModel.ts with a fixed seed to avoid leakage.
 */
export const LABELED_EMAILS: LabeledEmail[] = [
  phish("Urgent: verify your account immediately", "Your account has been suspended. Click here to verify your account immediately, or wire the funds to avoid suspension.", { urlCount: 1, urgency: 2, credentialRequest: 1, financialRequest: 1 }),
  phish("Confirm your identity now", "We noticed unusual sign-in activity. Confirm your identity and enter your password to keep your mailbox open.", { urlCount: 1, urgency: 1, credentialRequest: 2 }),
  phish("Your PayPal account will be limited", "Please log in to confirm your billing information or we will suspend withdrawals.", { urlCount: 1, credentialRequest: 1, urgency: 1 }),
  phish("Security alert: unauthorized login", "Click the link and verify your account immediately. Update your username and password today.", { urlCount: 1, urgency: 1, credentialRequest: 2 }),
  phish("Invoice attached - pay now", "Please process this payment and wire the funds to the account listed. Invoice attached.", { financialRequest: 2, urgency: 1 }),
  phish("IT Support: mailbox full", "Your mailbox is full. Sign in to confirm storage upgrade or email will bounce.", { credentialRequest: 1, urgency: 1 }),
  phish("Apple ID locked", "Your Apple ID was locked. Confirm your identity immediately to restore iCloud.", { urgency: 1, credentialRequest: 1 }),
  phish("Bank: unusual transfer", "We need you to make a payment and confirm your bank account and routing number.", { financialRequest: 2, credentialRequest: 1 }),
  phish("Gift card request from CEO", "I need you to buy gift cards immediately and send the codes. This is time sensitive.", { urgency: 2, financialRequest: 1 }),
  phish("Password expiring", "Your password expires tonight. Log in to confirm a new password or access is revoked.", { urgency: 1, credentialRequest: 1 }),
  phish("Document shared via Dropbox", "A file was shared with you. Click here to download the attachment and view payroll.", { urlCount: 1 }),
  phish("Refund pending", "Claim your refund. Verify your account and enter card details on the secure page.", { credentialRequest: 1, financialRequest: 1, urlCount: 1 }),
  phish("HR: update direct deposit", "Update your bank account for payroll. Confirm identity using the form.", { financialRequest: 1, credentialRequest: 1 }),
  phish("Microsoft 365 suspension", "Unusual activity. Verify now or your Office account is disabled.", { urgency: 1, credentialRequest: 1, urlCount: 1 }),
  phish("Delivery failed - fees due", "Package held. Pay customs with gift card or wire transfer immediately.", { financialRequest: 2, urgency: 1 }),
  phish("Shared OneDrive file", "You have a new encrypted voicemail. Open the attachment and enable macros.", { urlCount: 1 }),
  phish("Reset required", "We reset your password. Sign in to confirm the new credentials at this link.", { credentialRequest: 1, urlCount: 1 }),
  phish("Account verification needed", "Dear customer, verify your account immediately to avoid permanent closure.", { urgency: 1, credentialRequest: 1 }),
  phish("Unusual Amazon order", "We placed an order of $799. Cancel by logging in to your account page now.", { credentialRequest: 1, financialRequest: 1, urlCount: 1 }),
  phish("Tax refund", "You are eligible for a tax refund. Confirm identity and bank account to receive funds.", { financialRequest: 1, credentialRequest: 1 }),
  phish("VPN access disabled", "IT department: re-enable VPN. Enter username and password on this portal.", { credentialRequest: 1 }),
  phish("Suspended for spam", "Your mailbox was used to send spam. Click here to restore access immediately.", { urgency: 1, urlCount: 1 }),
  phish("New voicemail attached", "Please download the attachment to listen. It contains an invoice you must pay.", { financialRequest: 1 }),
  phish("Wire the remaining balance", "Per our call, wire the funds today to this bank account. Do not delay.", { financialRequest: 2, urgency: 1 }),
  phish("Confirm mailbox ownership", "Confirm your identity or we delete the mailbox. Act now.", { urgency: 2, credentialRequest: 1 }),
  phish("Crypto wallet locked", "Verify your wallet seed on this page to unlock withdrawals.", { credentialRequest: 1, financialRequest: 1, urlCount: 1 }),
  phish("Payroll correction", "We overpaid you. Refund via gift card immediately and reply with codes.", { financialRequest: 1, urgency: 1 }),
  phish("Security code", "Enter the one-time code and your password on the verification site.", { credentialRequest: 1, urlCount: 1 }),
  phish("Deactivation notice", "Your online banking will be deactivated. Verify your account to continue.", { credentialRequest: 1, urgency: 1 }),
  phish("Help desk ticket 8821", "Reset required. Log in to the help desk and confirm identity.", { credentialRequest: 1 }),
  phish("Limited-time prize", "You won a prize. Click here and provide bank account details to claim.", { financialRequest: 1, urlCount: 1, urgency: 1 }),
  phish("Failed payment", "Your last payment failed. Update now with card number and password.", { financialRequest: 1, credentialRequest: 1, urgency: 1 }),
  phish("Shared Google Doc", "A document requires you to sign in to confirm viewing permissions.", { credentialRequest: 1, urlCount: 1 }),
  phish("Urgent request from finance", "Process this payment before close of business. Routing number is in the thread.", { financialRequest: 1, urgency: 1 }),
  phish("Mailbox quota exceeded", "You have 24 hours. Click the link and sign in to increase quota.", { urgency: 1, credentialRequest: 1, urlCount: 1 }),
  phish("Verify device", "We do not recognize this device. Confirm your identity immediately.", { urgency: 1, credentialRequest: 1 }),
  phish("Netflix billing", "Your membership is on hold. Update now to keep watching.", { financialRequest: 1, urgency: 1, urlCount: 1 }),
  phish("COVID relief funds", "Claim relief. Confirm identity and bank account on the government look-alike form.", { financialRequest: 1, credentialRequest: 1 }),
  phish("DocuSign: review contract", "Review and sign. The portal asks for your password to authenticate.", { credentialRequest: 1, urlCount: 1 }),
  phish("Last warning", "Final notice. Verify your account immediately or it is deleted.", { urgency: 2, credentialRequest: 1 }),

  ham("Weekly digest", "Here is your weekly digest of company news and updates."),
  ham("Test scan", "This is a test body."),
  ham("Meeting notes from Tuesday", "Thanks for joining. Action items are in the shared notes. See you next week."),
  ham("Project status", "Sprint 14 is on track. No blockers. Please review the dashboard when you have time."),
  ham("Lunch tomorrow?", "Want to grab lunch near the office tomorrow at noon?"),
  ham("Invoice 1842 for April", "Attached is the monthly invoice for contracted work completed in April. Net 30 as usual."),
  ham("Welcome to the mailing list", "You subscribed to our product newsletter. You can unsubscribe at any time."),
  ham("Git commit failed on CI", "The build failed on the typecheck job. Logs are in the pipeline page."),
  ham("Office closed Friday", "HR reminder: the office is closed this Friday for the public holiday."),
  ham("Your order has shipped", "Your order 1182 shipped via ground. Tracking is in your account. Thank you for shopping with us."),
  ham("Calendar invite accepted", "Alex accepted your calendar invite for Thursday 3pm."),
  ham("Quarterly report draft", "First draft of the Q2 report is in the drive folder. Comments welcome by Friday."),
  ham("Password changed", "This is a confirmation that you changed your password from the account settings page. If you did this, no action is needed."),
  ham("New comment on ticket", "Jane commented on TICKET-441: the patch is ready for review."),
  ham("Family photos", "Uploading the reunion photos to the shared album this weekend."),
  ham("Library book due", "Your library book is due next Wednesday. You can renew online."),
  ham("Conference recap", "Thanks to everyone who presented. Slides will be posted on the intranet."),
  ham("Weekly digest of company news and updates", "Highlights this week: hiring, benefits enrollment, and the cafeteria menu."),
  ham("Subscription receipt", "Thanks for renewing. This email is your receipt for the annual plan."),
  ham("Server maintenance window", "We will patch the staging cluster Saturday 02:00–04:00 UTC. No production impact."),
  ham("Thank you for your purchase", "We received your payment. Your license key is listed below."),
  ham("Team offsite agenda", "Agenda attached. Please arrive by 9:00. Lunch is provided."),
  ham("Code review ping", "Can you look at PR 88 when you get a chance? Tests are green."),
  ham("Happy birthday", "Hope you have a great day. Cake in the kitchen at 4."),
  ham("Newsletter: engineering blog", "This month we wrote about database indexes and query plans."),
  ham("Flight itinerary", "Your booking is confirmed. Check-in opens 24 hours before departure."),
  ham("School PTA minutes", "Minutes from last night's PTA meeting are attached as a PDF."),
  ham("Research paper submission", "We submitted the camera-ready version. Reviews were overall positive."),
  ham("Parking permit renewal", "Your permit renews automatically. No further action unless your vehicle changed."),
  ham("Welcome aboard", "Excited to have you on the team. Orientation is Monday in room 12."),
  ham("Backup completed", "Nightly backup finished successfully. 1.2 TB copied with no errors."),
  ham("Weather delay", "The event is postponed due to weather. New date to follow."),
  ham("Please review the attached contract", "Legal asked us to review clause 4. Compensation terms are unchanged."),
  ham("Standup notes", "Yesterday: finished the parser tests. Today: header forensics. Blockers: none."),
  ham("Doctor appointment reminder", "Reminder: appointment on Thursday at 10:30. Reply if you need to reschedule."),
  ham("Open source release", "v0.1.0 is tagged. Changelog is in the repository README."),
  ham("Book club", "Next book is due in two weeks. Meeting at the usual cafe."),
  ham("Hello", "Just checking in about the design mockups. No rush."),
  ham("hi", "hello"),
  ham("Re: weekly digest", "Thanks, the cafeteria note was helpful. See you at the all-hands."),
  ham("Delivery notification", "Your office supplies were left at reception. Packing slip 5521."),
];
