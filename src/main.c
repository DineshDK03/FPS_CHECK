#include <zephyr.h>
#include <device.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <drivers/uart.h>


#define FINGERPRINT_STARTCODE 0xEF01

#define FINGERPRINT_OK 0x00

#define FINGERPRINT_VERIFYPASSWORD 0x13
#define FPM_CHECKSENSOR 0x36
#define FPM_FIRMWARE_CHECK 0x3A
#define FPM_DEFAULT_TIMEOUT 1000

#define FPM_COMMANDPACKET 0x1
#define FINGERPRINT_ACKPACKET 0x7

#define FINGERPRINT_TIMEOUT 0xFF
#define FINGERPRINT_BADPACKET 0xFE

#define UART_DEVICE_NAME DT_LABEL(DT_NODELABEL(uart3))

int verify_passwd(void)
{
  static uint8_t get_packet[10];
  const struct device *uart_dev = device_get_binding(UART_DEVICE_NAME);

  uint16_t sum = FPM_COMMANDPACKET + 0x00 + 0x03 + FINGERPRINT_VERIFYPASSWORD + 0x00 + 0x00 + 0x00 + 0x00;

  uint8_t pkg_data[] = {
          FINGERPRINT_STARTCODE >> 8,
          FINGERPRINT_STARTCODE & 0xFF,
          0xFF,0xFF,0xFF,0xFF,
          FPM_COMMANDPACKET,
          0x00,0x03,
          FINGERPRINT_VERIFYPASSWORD,
          0x00,0x00,0x00,0x00,
          sum >> 8,sum & 0xFF
  };

  for(uint8_t i = 0;i<sizeof(pkg_data);i++) {
    printk("0x%X\n",pkg_data[i]);
    uart_poll_out(uart_dev, pkg_data[i]);
  }

  uint64_t end = sys_clock_timeout_end_calc(K_MSEC(FPM_DEFAULT_TIMEOUT));
  int i = 0;

  while (1) {
    uint8_t c;
    int64_t remaining = end - sys_clock_tick_get();

		if (remaining <= 0) {
			return FINGERPRINT_TIMEOUT;
		}

    if (uart_poll_in(uart_dev, &c) == 0) {
      get_packet[i++] = c;
      if (i == 10) {
        break;
      }
    }
  }

  if (get_packet[6] != FINGERPRINT_ACKPACKET) {
    printk("ACK packet error 0x%X\n",get_packet[6]);
    return FINGERPRINT_BADPACKET;
  }

  if (get_packet[9]  == FINGERPRINT_OK) {
    printk("FPS Device Found %X\n",get_packet[9]);
  } else {
    printk("FPS Device not found");
  }

  return 0;

}

int check_firmware(void)
{
  const struct device *uart_dev = device_get_binding(UART_DEVICE_NAME);
  uint8_t new_get_packet[33];
  uint16_t new_sum = FPM_COMMANDPACKET + 0x00 + 0x03 + FPM_FIRMWARE_CHECK;

  uint8_t new_pkg_data[] = {
          FINGERPRINT_STARTCODE >> 8,
          FINGERPRINT_STARTCODE & 0xFF,
          0xFF,0xFF,0xFF,0xFF,
          FPM_COMMANDPACKET,
          0x00,0x03,
          FPM_FIRMWARE_CHECK,
          new_sum >> 8,new_sum & 0xFF
  };

  for(uint8_t i = 0;i<sizeof(new_pkg_data);i++) {
    uart_poll_out(uart_dev, new_pkg_data[i]);
  }

  uint64_t end = sys_clock_timeout_end_calc(K_MSEC(FPM_DEFAULT_TIMEOUT));
  int i = 0;

  while (1) {
    uint8_t c;
    int64_t remaining = end - sys_clock_tick_get();

		if (remaining <= 0) {
			return -EIO;
		}

    if (uart_poll_in(uart_dev, &c) == 0) {
      new_get_packet[i++] = c;
      if (i == 33) {
        break;
      }
    }
  }

  if (new_get_packet[6] != FINGERPRINT_ACKPACKET) {
    printk("ACK packet error 0x%X\n",new_get_packet[6]);
    return FINGERPRINT_BADPACKET;
  }

  if (new_get_packet[9] == FINGERPRINT_OK) {
    printk("Check firmware OK %X\n",new_get_packet[9]);
  } else {
    printk("pakcet not received\n");
  }

  for(uint8_t i = 10; i<sizeof(new_get_packet);i++)
  printk("data received 0x%X\r",new_get_packet[i]);

  return 0;
}

int main(void)
{
  uint8_t ret;
  bool passwd = false;
  const struct device *uart_dev = device_get_binding(UART_DEVICE_NAME);
  if (!uart_dev) {
          printk("Cannot get UART device\n");
  }

  k_msleep(500);

  ret = verify_passwd();
  if(ret == 0) {
    printk("Verify Password Success\n");
    passwd = true;
  } else {
    printk("Error Occured 0x%X\n",ret);
  }

  if(passwd) {
    ret = check_firmware();
    if(ret == 0) {
      printk("Firmware check Success\n");
    } else {
      printk("Error Occured 0x%X\n",ret);
    }
  }


  return 0;
}
