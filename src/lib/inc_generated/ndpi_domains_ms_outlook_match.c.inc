/*
 *
 * This file is generated automatically and part of nDPI
 *
 * nDPI is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * nDPI is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with nDPI.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

/* ****************************************************** */


static ndpi_protocol_match outlook_host_match[] = {
 { "mail.protection.outlook.com", "Outlook", NDPI_PROTOCOL_MS_OUTLOOK, NDPI_PROTOCOL_CATEGORY_MAIL, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_DEFAULT_LEVEL },
 { "mx.microsoft", "Outlook", NDPI_PROTOCOL_MS_OUTLOOK, NDPI_PROTOCOL_CATEGORY_MAIL, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_DEFAULT_LEVEL },
 { "outlook.cloud.microsoft", "Outlook", NDPI_PROTOCOL_MS_OUTLOOK, NDPI_PROTOCOL_CATEGORY_MAIL, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_DEFAULT_LEVEL },
 { "outlook.com", "Outlook", NDPI_PROTOCOL_MS_OUTLOOK, NDPI_PROTOCOL_CATEGORY_MAIL, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_DEFAULT_LEVEL },
 { "outlook.office365.com", "Outlook", NDPI_PROTOCOL_MS_OUTLOOK, NDPI_PROTOCOL_CATEGORY_MAIL, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_DEFAULT_LEVEL },
 { "outlook.office.com", "Outlook", NDPI_PROTOCOL_MS_OUTLOOK, NDPI_PROTOCOL_CATEGORY_MAIL, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_DEFAULT_LEVEL },
 { "protection.outlook.com", "Outlook", NDPI_PROTOCOL_MS_OUTLOOK, NDPI_PROTOCOL_CATEGORY_MAIL, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_DEFAULT_LEVEL },
 { "smtp.office365.com", "Outlook", NDPI_PROTOCOL_MS_OUTLOOK, NDPI_PROTOCOL_CATEGORY_MAIL, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_DEFAULT_LEVEL },
 { NULL, NULL, NDPI_PROTOCOL_UNKNOWN, NDPI_PROTOCOL_CATEGORY_UNSPECIFIED, NDPI_PROTOCOL_SAFE, NDPI_PROTOCOL_DEFAULT_LEVEL }
};
