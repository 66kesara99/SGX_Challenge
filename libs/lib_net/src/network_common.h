/*
 * common.h
 *
 *  Created on: Jul 21, 2017
 */

#ifndef NETWORK_NETWORK_COMMON_H_
#define NETWORK_NETWORK_COMMON_H_

#include <boost/asio.hpp>
#include "network_types.h"

using boost::asio::ip::tcp;

boost::system::error_code send_message_read_response(tcp::socket* s, message_t *msg, message_t *resp);
boost::system::error_code read_message(tcp::socket* s, message_t *msg);
boost::system::error_code send_message(tcp::socket* s, message_t *msg);

#endif /* NETWORK_NETWORK_COMMON_H_ */
