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


static ndpi_protocol_match aws_ec2_host_match[] = {
 { "compute-1.amazonaws.com", "AWS_EC2", NDPI_PROTOCOL_AWS_EC2, NDPI_PROTOCOL_CATEGORY_CLOUD, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_DEFAULT_LEVEL },
 { "compute.amazonaws.com", "AWS_EC2", NDPI_PROTOCOL_AWS_EC2, NDPI_PROTOCOL_CATEGORY_CLOUD, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_DEFAULT_LEVEL },
 { "compute.amazonaws.com.cn", "AWS_EC2", NDPI_PROTOCOL_AWS_EC2, NDPI_PROTOCOL_CATEGORY_CLOUD, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_DEFAULT_LEVEL },
 { NULL, NULL, NDPI_PROTOCOL_UNKNOWN, NDPI_PROTOCOL_CATEGORY_UNSPECIFIED, NDPI_PROTOCOL_SAFE, NDPI_PROTOCOL_DEFAULT_LEVEL }
};
