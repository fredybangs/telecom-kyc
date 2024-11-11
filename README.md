# QCell KYC Odoo Module

## Overview

The **Telecom KYC** Odoo module is designed to streamline and manage Know Your Customer (KYC) processes for QCell, enabling agents to efficiently create, verify, and manage client information and documents for identity verification. This module supports document upload, customer information storage, and KYC application state management to ensure compliance with regulatory requirements.

## Features

- **KYC Application Creation**: Allows agents to create KYC applications on behalf of customers.
- **Document Upload**: Supports uploading of ID documents, proof of address, and customer selfies.
- **Application State Management**: Manages KYC application states (e.g., draft, submitted, verified, rejected).
- **Permissions & Access Control**: Provides role-based access for creators, verifiers, and administrators.
- **Integration with Mobile App**: Accessible via the QCell KYC mobile app (built with Expo), allowing agents to manage KYC applications on the go.

## Requirements

- **Odoo 17**
- **Expo (for the mobile app client)**
- **Client App - https://github.com/fredybangs/kyc-client**
- **Agent App - https://github.com/fredybangs/kyc-agent**

## Installation

1. **Clone the Module Repository**:
   Clone or download the Telecom KYC module into your Odoo `addons` directory.

2. **Activate the Module**:
   - Go to **Apps** in your Odoo instance.
   - Click on **Update Apps List**.
   - Search for "QCell KYC" and click **Install**.

3. **Dependencies**:
   Ensure the following dependencies are installed:
   - Required Odoo modules (Contacts, Documents, etc.)
   - External libraries for the Expo app if applicable (e.g., `axios`, `redux`, `expo-image-picker`).

## Usage

### Key Entities

- **KYC Applications**: Represent individual customer KYC records.
- **Customers**: Stored in `res.partner` with additional fields for KYC applications.

### How to Use

1. **Creating a KYC Application**:
   - Agents can create KYC applications directly in Odoo or through the mobile app.
   - Each application includes fields like `ID Type`, `ID Number`, and URLs for document images.

2. **Managing Application States**:
   - KYC applications go through different states: **Draft**, **Submitted**, **Verified**, and **Rejected**.
   - Users with appropriate permissions can change the state and add verification notes.

3. **Accessing and Filtering KYC Applications**:
   - The module provides a menu and tree view to view all KYC applications.
   - The `res.partner` form is extended to display related KYC applications.

### Mobile Application Integration

- The mobile app built with Expo allows agents to:
  - Create KYC applications
  - Upload images for ID, proof of address, and selfies
  - Manage application states and add notes

## API Endpoints

The Odoo module exposes the following endpoints for integration with the mobile app:

- **Create KYC Application**: `POST /api/kyc/create`
  - Body: JSON payload containing user and KYC application data.
  - Headers: Access Token for authorization.
  
## Roles & Permissions

1. **Creator**: Can create and submit KYC applications.
2. **Verifier**: Can verify and approve/reject applications.
3. **Admin**: Full control over all application states and roles.

## Module Structure

- **Models**:
  - `qcell_kyc.application`: Defines the KYC application structure.
  - Inherits `res.partner` to link customers to KYC applications.

- **Views**:
  - Form and tree views for KYC applications.
  - Integration of KYC information on the `res.partner` form.

- **Security**:
  - Access rights and record rules defined in `security/ir.model.access.csv` for role-based access.

## Configuration

- **Primary Color**: The primary brand color used in the application is `#F58F21`, ensuring brand consistency across the platform and mobile app.
- **Image Upload**: Images are uploaded via an external API (e.g., ImgBB) from the mobile app and stored as URLs in the KYC application records.

## Development Tools Used

- **Backend**:
  - Odoo 17
  - Python
- **Mobile Client**:
  - Expo (React Native)
  - Axios for API calls
  - Redux for state management
  - Expo Image Picker and ImgBB API for image handling

---

## Support

For support and further documentation, contact The SpaceMan - https://thespaceman.tech.

--- 
