

/**
  ******************************************************************************
  * @file    bluenrg1_hal_aci.c
  * @author  AMG - RF Application team
  * @version V1.0.0
  * @date    31 May 2018
  * @brief   Source file for external uC - BlueNRG-x in network coprocessor mode (hal_aci)
  *          Autogenerated files, do not edit!!
  ******************************************************************************
  * @attention
  *
  * THE PRESENT FIRMWARE WHICH IS FOR GUIDANCE ONLY AIMS AT PROVIDING CUSTOMERS
  * WITH CODING INFORMATION REGARDING THEIR PRODUCTS IN ORDER FOR THEM TO SAVE
  * TIME. AS A RESULT, STMICROELECTRONICS SHALL NOT BE HELD LIABLE FOR ANY
  * DIRECT, INDIRECT OR CONSEQUENTIAL DAMAGES WITH RESPECT TO ANY CLAIMS ARISING
  * FROM THE CONTENT OF SUCH FIRMWARE AND/OR THE USE MADE BY CUSTOMERS OF THE
  * CODING INFORMATION CONTAINED HEREIN IN CONNECTION WITH THEIR PRODUCTS.
  *
  * <h2><center>&copy; COPYRIGHT STMicroelectronics</center></h2>
  ******************************************************************************
  */
#include "bluenrg1_hal_aci.h"
#include "osal.h"
tBleStatus aci_hal_get_fw_build_number(uint16_t *Build_Number)
{
  struct hci_request rq;
  aci_hal_get_fw_build_number_rp0 resp;
  Osal_MemSet(&resp, 0, sizeof(resp));
  Osal_MemSet(&rq, 0, sizeof(rq));
  rq.ogf = 0x3f;
  rq.ocf = 0x000;
  rq.rparam = &resp;
  rq.rlen = sizeof(resp);
  if (hci_send_req(&rq, FALSE) < 0)
    return BLE_STATUS_TIMEOUT;
  if (resp.Status) {
    return resp.Status;
  }
  *Build_Number = btoh(resp.Build_Number, 2);
  return BLE_STATUS_SUCCESS;
}
tBleStatus aci_hal_get_firmware_details(uint8_t *DTM_version_major,
                                        uint8_t *DTM_version_minor,
                                        uint8_t *DTM_version_patch,
                                        uint8_t *DTM_variant,
                                        uint16_t *DTM_Build_Number,
                                        uint8_t *BTLE_Stack_version_major,
                                        uint8_t *BTLE_Stack_version_minor,
                                        uint8_t *BTLE_Stack_version_patch,
                                        uint8_t *BTLE_Stack_development,
                                        uint16_t *BTLE_Stack_variant,
                                        uint16_t *BTLE_Stack_Build_Number)
{
  struct hci_request rq;
  aci_hal_get_firmware_details_rp0 resp;
  Osal_MemSet(&resp, 0, sizeof(resp));
  Osal_MemSet(&rq, 0, sizeof(rq));
  rq.ogf = 0x3f;
  rq.ocf = 0x001;
  rq.rparam = &resp;
  rq.rlen = sizeof(resp);
  if (hci_send_req(&rq, FALSE) < 0)
    return BLE_STATUS_TIMEOUT;
  if (resp.Status) {
    return resp.Status;
  }
  *DTM_version_major = btoh(resp.DTM_version_major, 1);
  *DTM_version_minor = btoh(resp.DTM_version_minor, 1);
  *DTM_version_patch = btoh(resp.DTM_version_patch, 1);
  *DTM_variant = btoh(resp.DTM_variant, 1);
  *DTM_Build_Number = btoh(resp.DTM_Build_Number, 2);
  *BTLE_Stack_version_major = btoh(resp.BTLE_Stack_version_major, 1);
  *BTLE_Stack_version_minor = btoh(resp.BTLE_Stack_version_minor, 1);
  *BTLE_Stack_version_patch = btoh(resp.BTLE_Stack_version_patch, 1);
  *BTLE_Stack_development = btoh(resp.BTLE_Stack_development, 1);
  *BTLE_Stack_variant = btoh(resp.BTLE_Stack_variant, 2);
  *BTLE_Stack_Build_Number = btoh(resp.BTLE_Stack_Build_Number, 2);
  return BLE_STATUS_SUCCESS;
}
tBleStatus aci_hal_write_config_data(uint8_t Offset,
                                     uint8_t Length,
                                     uint8_t Value[])
{
  struct hci_request rq;
  uint8_t cmd_buffer[258];
  aci_hal_write_config_data_cp0 *cp0 = (aci_hal_write_config_data_cp0*)(cmd_buffer);
  tBleStatus status = 0;
  uint8_t index_input = 0;
  cp0->Offset = htob(Offset, 1);
  index_input += 1;
  cp0->Length = htob(Length, 1);
  index_input += 1;
  /* var_len_data input */
  {
    Osal_MemCpy((void *) &cp0->Value, (const void *) Value, Length);
    index_input += Length;
  }
  Osal_MemSet(&rq, 0, sizeof(rq));
  rq.ogf = 0x3f;
  rq.ocf = 0x00c;
  rq.cparam = cmd_buffer;
  rq.clen = index_input;
  rq.rparam = &status;
  rq.rlen = 1;
  if (hci_send_req(&rq, FALSE) < 0)
    return BLE_STATUS_TIMEOUT;
  if (status) {
    return status;
  }
  return BLE_STATUS_SUCCESS;
}
tBleStatus aci_hal_read_config_data(uint8_t Offset,
                                    uint8_t *Data_Length,
                                    uint8_t Data[])
{
  struct hci_request rq;
  uint8_t cmd_buffer[258];
  aci_hal_read_config_data_cp0 *cp0 = (aci_hal_read_config_data_cp0*)(cmd_buffer);
  aci_hal_read_config_data_rp0 resp;
  Osal_MemSet(&resp, 0, sizeof(resp));
  uint8_t index_input = 0;
  cp0->Offset = htob(Offset, 1);
  index_input += 1;
  Osal_MemSet(&rq, 0, sizeof(rq));
  rq.ogf = 0x3f;
  rq.ocf = 0x00d;
  rq.cparam = cmd_buffer;
  rq.clen = index_input;
  rq.rparam = &resp;
  rq.rlen = sizeof(resp);
  if (hci_send_req(&rq, FALSE) < 0)
    return BLE_STATUS_TIMEOUT;
  if (resp.Status) {
    return resp.Status;
  }
  *Data_Length = btoh(resp.Data_Length, 1);
  Osal_MemCpy((void *) Data, (const void *) resp.Data, *Data_Length);
  return BLE_STATUS_SUCCESS;
}
tBleStatus aci_hal_set_tx_power_level(uint8_t En_High_Power,
                                      uint8_t PA_Level)
{
  struct hci_request rq;
  uint8_t cmd_buffer[258];
  aci_hal_set_tx_power_level_cp0 *cp0 = (aci_hal_set_tx_power_level_cp0*)(cmd_buffer);
  tBleStatus status = 0;
  uint8_t index_input = 0;
  cp0->En_High_Power = htob(En_High_Power, 1);
  index_input += 1;
  cp0->PA_Level = htob(PA_Level, 1);
  index_input += 1;
  Osal_MemSet(&rq, 0, sizeof(rq));
  rq.ogf = 0x3f;
  rq.ocf = 0x00f;
  rq.cparam = cmd_buffer;
  rq.clen = index_input;
  rq.rparam = &status;
  rq.rlen = 1;
  if (hci_send_req(&rq, FALSE) < 0)
    return BLE_STATUS_TIMEOUT;
  if (status) {
    return status;
  }
  return BLE_STATUS_SUCCESS;
}
tBleStatus aci_hal_le_tx_test_packet_number(uint32_t *Number_Of_Packets)
{
  struct hci_request rq;
  aci_hal_le_tx_test_packet_number_rp0 resp;
  Osal_MemSet(&resp, 0, sizeof(resp));
  Osal_MemSet(&rq, 0, sizeof(rq));
  rq.ogf = 0x3f;
  rq.ocf = 0x014;
  rq.rparam = &resp;
  rq.rlen = sizeof(resp);
  if (hci_send_req(&rq, FALSE) < 0)
    return BLE_STATUS_TIMEOUT;
  if (resp.Status) {
    return resp.Status;
  }
  *Number_Of_Packets = btoh(resp.Number_Of_Packets, 4);
  return BLE_STATUS_SUCCESS;
}
tBleStatus aci_hal_tone_start(uint8_t RF_Channel,
                              uint8_t Offset)
{
  struct hci_request rq;
  uint8_t cmd_buffer[258];
  aci_hal_tone_start_cp0 *cp0 = (aci_hal_tone_start_cp0*)(cmd_buffer);
  tBleStatus status = 0;
  uint8_t index_input = 0;
  cp0->RF_Channel = htob(RF_Channel, 1);
  index_input += 1;
  cp0->Offset = htob(Offset, 1);
  index_input += 1;
  Osal_MemSet(&rq, 0, sizeof(rq));
  rq.ogf = 0x3f;
  rq.ocf = 0x015;
  rq.cparam = cmd_buffer;
  rq.clen = index_input;
  rq.rparam = &status;
  rq.rlen = 1;
  if (hci_send_req(&rq, FALSE) < 0)
    return BLE_STATUS_TIMEOUT;
  if (status) {
    return status;
  }
  return BLE_STATUS_SUCCESS;
}
tBleStatus aci_hal_tone_stop(void)
{
  struct hci_request rq;
  tBleStatus status = 0;
  Osal_MemSet(&rq, 0, sizeof(rq));
  rq.ogf = 0x3f;
  rq.ocf = 0x016;
  rq.rparam = &status;
  rq.rlen = 1;
  if (hci_send_req(&rq, FALSE) < 0)
    return BLE_STATUS_TIMEOUT;
  if (status) {
    return status;
  }
  return BLE_STATUS_SUCCESS;
}
tBleStatus aci_hal_get_link_status(uint8_t Link_Status[8],
                                   uint16_t Link_Connection_Handle[16 / 2])
{
  struct hci_request rq;
  aci_hal_get_link_status_rp0 resp;
  Osal_MemSet(&resp, 0, sizeof(resp));
  Osal_MemSet(&rq, 0, sizeof(rq));
  rq.ogf = 0x3f;
  rq.ocf = 0x017;
  rq.rparam = &resp;
  rq.rlen = sizeof(resp);
  if (hci_send_req(&rq, FALSE) < 0)
    return BLE_STATUS_TIMEOUT;
  if (resp.Status) {
    return resp.Status;
  }
  Osal_MemCpy((void *) Link_Status, (const void *) resp.Link_Status, 8);
  Osal_MemCpy((void *) Link_Connection_Handle, (const void *) resp.Link_Connection_Handle, 16);
  return BLE_STATUS_SUCCESS;
}
tBleStatus aci_hal_set_radio_activity_mask(uint16_t Radio_Activity_Mask)
{
  struct hci_request rq;
  uint8_t cmd_buffer[258];
  aci_hal_set_radio_activity_mask_cp0 *cp0 = (aci_hal_set_radio_activity_mask_cp0*)(cmd_buffer);
  tBleStatus status = 0;
  uint8_t index_input = 0;
  cp0->Radio_Activity_Mask = htob(Radio_Activity_Mask, 2);
  index_input += 2;
  Osal_MemSet(&rq, 0, sizeof(rq));
  rq.ogf = 0x3f;
  rq.ocf = 0x018;
  rq.cparam = cmd_buffer;
  rq.clen = index_input;
  rq.rparam = &status;
  rq.rlen = 1;
  if (hci_send_req(&rq, FALSE) < 0)
    return BLE_STATUS_TIMEOUT;
  if (status) {
    return status;
  }
  return BLE_STATUS_SUCCESS;
}
tBleStatus aci_hal_get_anchor_period(uint32_t *Anchor_Period,
                                     uint32_t *Max_Free_Slot)
{
  struct hci_request rq;
  aci_hal_get_anchor_period_rp0 resp;
  Osal_MemSet(&resp, 0, sizeof(resp));
  Osal_MemSet(&rq, 0, sizeof(rq));
  rq.ogf = 0x3f;
  rq.ocf = 0x019;
  rq.rparam = &resp;
  rq.rlen = sizeof(resp);
  if (hci_send_req(&rq, FALSE) < 0)
    return BLE_STATUS_TIMEOUT;
  if (resp.Status) {
    return resp.Status;
  }
  *Anchor_Period = btoh(resp.Anchor_Period, 4);
  *Max_Free_Slot = btoh(resp.Max_Free_Slot, 4);
  return BLE_STATUS_SUCCESS;
}
tBleStatus aci_hal_set_event_mask(uint32_t Event_Mask)
{
  struct hci_request rq;
  uint8_t cmd_buffer[258];
  aci_hal_set_event_mask_cp0 *cp0 = (aci_hal_set_event_mask_cp0*)(cmd_buffer);
  tBleStatus status = 0;
  uint8_t index_input = 0;
  cp0->Event_Mask = htob(Event_Mask, 4);
  index_input += 4;
  Osal_MemSet(&rq, 0, sizeof(rq));
  rq.ogf = 0x3f;
  rq.ocf = 0x01a;
  rq.cparam = cmd_buffer;
  rq.clen = index_input;
  rq.rparam = &status;
  rq.rlen = 1;
  if (hci_send_req(&rq, FALSE) < 0)
    return BLE_STATUS_TIMEOUT;
  if (status) {
    return status;
  }
  return BLE_STATUS_SUCCESS;
}
tBleStatus aci_hal_updater_start(void)
{
  struct hci_request rq;
  tBleStatus status = 0;
  Osal_MemSet(&rq, 0, sizeof(rq));
  rq.ogf = 0x3f;
  rq.ocf = 0x020;
  rq.rparam = &status;
  rq.rlen = 1;
  if (hci_send_req(&rq, FALSE) < 0)
    return BLE_STATUS_TIMEOUT;
  if (status) {
    return status;
  }
  return BLE_STATUS_SUCCESS;
}
tBleStatus aci_hal_updater_reboot(void)
{
  struct hci_request rq;
  tBleStatus status = 0;
  Osal_MemSet(&rq, 0, sizeof(rq));
  rq.ogf = 0x3f;
  rq.ocf = 0x021;
  rq.rparam = &status;
  rq.rlen = 1;
  if (hci_send_req(&rq, FALSE) < 0)
    return BLE_STATUS_TIMEOUT;
  if (status) {
    return status;
  }
  return BLE_STATUS_SUCCESS;
}
tBleStatus aci_hal_get_updater_version(uint8_t *Version)
{
  struct hci_request rq;
  aci_hal_get_updater_version_rp0 resp;
  Osal_MemSet(&resp, 0, sizeof(resp));
  Osal_MemSet(&rq, 0, sizeof(rq));
  rq.ogf = 0x3f;
  rq.ocf = 0x022;
  rq.rparam = &resp;
  rq.rlen = sizeof(resp);
  if (hci_send_req(&rq, FALSE) < 0)
    return BLE_STATUS_TIMEOUT;
  if (resp.Status) {
    return resp.Status;
  }
  *Version = btoh(resp.Version, 1);
  return BLE_STATUS_SUCCESS;
}
tBleStatus aci_hal_get_updater_bufsize(uint8_t *Buffer_Size)
{
  struct hci_request rq;
  aci_hal_get_updater_bufsize_rp0 resp;
  Osal_MemSet(&resp, 0, sizeof(resp));
  Osal_MemSet(&rq, 0, sizeof(rq));
  rq.ogf = 0x3f;
  rq.ocf = 0x023;
  rq.rparam = &resp;
  rq.rlen = sizeof(resp);
  if (hci_send_req(&rq, FALSE) < 0)
    return BLE_STATUS_TIMEOUT;
  if (resp.Status) {
    return resp.Status;
  }
  *Buffer_Size = btoh(resp.Buffer_Size, 1);
  return BLE_STATUS_SUCCESS;
}
tBleStatus aci_hal_updater_erase_blue_flag(void)
{
  struct hci_request rq;
  tBleStatus status = 0;
  Osal_MemSet(&rq, 0, sizeof(rq));
  rq.ogf = 0x3f;
  rq.ocf = 0x024;
  rq.rparam = &status;
  rq.rlen = 1;
  if (hci_send_req(&rq, FALSE) < 0)
    return BLE_STATUS_TIMEOUT;
  if (status) {
    return status;
  }
  return BLE_STATUS_SUCCESS;
}
tBleStatus aci_hal_updater_reset_blue_flag(void)
{
  struct hci_request rq;
  tBleStatus status = 0;
  Osal_MemSet(&rq, 0, sizeof(rq));
  rq.ogf = 0x3f;
  rq.ocf = 0x025;
  rq.rparam = &status;
  rq.rlen = 1;
  if (hci_send_req(&rq, FALSE) < 0)
    return BLE_STATUS_TIMEOUT;
  if (status) {
    return status;
  }
  return BLE_STATUS_SUCCESS;
}
tBleStatus aci_hal_updater_erase_sector(uint32_t Address)
{
  struct hci_request rq;
  uint8_t cmd_buffer[258];
  aci_hal_updater_erase_sector_cp0 *cp0 = (aci_hal_updater_erase_sector_cp0*)(cmd_buffer);
  tBleStatus status = 0;
  uint8_t index_input = 0;
  cp0->Address = htob(Address, 4);
  index_input += 4;
  Osal_MemSet(&rq, 0, sizeof(rq));
  rq.ogf = 0x3f;
  rq.ocf = 0x026;
  rq.cparam = cmd_buffer;
  rq.clen = index_input;
  rq.rparam = &status;
  rq.rlen = 1;
  if (hci_send_req(&rq, FALSE) < 0)
    return BLE_STATUS_TIMEOUT;
  if (status) {
    return status;
  }
  return BLE_STATUS_SUCCESS;
}
tBleStatus aci_hal_updater_prog_data_blk(uint32_t Address,
                                         uint16_t Data_Length,
                                         uint8_t Data[])
{
  struct hci_request rq;
  uint8_t cmd_buffer[258];
  aci_hal_updater_prog_data_blk_cp0 *cp0 = (aci_hal_updater_prog_data_blk_cp0*)(cmd_buffer);
  tBleStatus status = 0;
  uint8_t index_input = 0;
  cp0->Address = htob(Address, 4);
  index_input += 4;
  cp0->Data_Length = htob(Data_Length, 2);
  index_input += 2;
  /* var_len_data input */
  {
    Osal_MemCpy((void *) &cp0->Data, (const void *) Data, Data_Length);
    index_input += Data_Length;
  }
  Osal_MemSet(&rq, 0, sizeof(rq));
  rq.ogf = 0x3f;
  rq.ocf = 0x027;
  rq.cparam = cmd_buffer;
  rq.clen = index_input;
  rq.rparam = &status;
  rq.rlen = 1;
  if (hci_send_req(&rq, FALSE) < 0)
    return BLE_STATUS_TIMEOUT;
  if (status) {
    return status;
  }
  return BLE_STATUS_SUCCESS;
}
tBleStatus aci_hal_updater_read_data_blk(uint32_t Address,
                                         uint16_t Data_Length,
                                         uint8_t Data[])
{
  struct hci_request rq;
  uint8_t cmd_buffer[258];
  aci_hal_updater_read_data_blk_cp0 *cp0 = (aci_hal_updater_read_data_blk_cp0*)(cmd_buffer);
  aci_hal_updater_read_data_blk_rp0 resp;
  Osal_MemSet(&resp, 0, sizeof(resp));
  uint8_t index_input = 0;
  cp0->Address = htob(Address, 4);
  index_input += 4;
  cp0->Data_Length = htob(Data_Length, 2);
  index_input += 2;
  Osal_MemSet(&rq, 0, sizeof(rq));
  rq.ogf = 0x3f;
  rq.ocf = 0x028;
  rq.cparam = cmd_buffer;
  rq.clen = index_input;
  rq.rparam = &resp;
  rq.rlen = sizeof(resp);
  if (hci_send_req(&rq, FALSE) < 0)
    return BLE_STATUS_TIMEOUT;
  if (resp.Status) {
    return resp.Status;
  }
  Osal_MemCpy((void *) Data, (const void *) resp.Data, *Data);
  return BLE_STATUS_SUCCESS;
}
tBleStatus aci_hal_updater_calc_crc(uint32_t Address,
                                    uint8_t Num_Of_Sectors,
                                    uint32_t *crc)
{
  struct hci_request rq;
  uint8_t cmd_buffer[258];
  aci_hal_updater_calc_crc_cp0 *cp0 = (aci_hal_updater_calc_crc_cp0*)(cmd_buffer);
  aci_hal_updater_calc_crc_rp0 resp;
  Osal_MemSet(&resp, 0, sizeof(resp));
  uint8_t index_input = 0;
  cp0->Address = htob(Address, 4);
  index_input += 4;
  cp0->Num_Of_Sectors = htob(Num_Of_Sectors, 1);
  index_input += 1;
  Osal_MemSet(&rq, 0, sizeof(rq));
  rq.ogf = 0x3f;
  rq.ocf = 0x029;
  rq.cparam = cmd_buffer;
  rq.clen = index_input;
  rq.rparam = &resp;
  rq.rlen = sizeof(resp);
  if (hci_send_req(&rq, FALSE) < 0)
    return BLE_STATUS_TIMEOUT;
  if (resp.Status) {
    return resp.Status;
  }
  *crc = btoh(resp.crc, 4);
  return BLE_STATUS_SUCCESS;
}
tBleStatus aci_hal_updater_hw_version(uint8_t *HW_Version)
{
  struct hci_request rq;
  aci_hal_updater_hw_version_rp0 resp;
  Osal_MemSet(&resp, 0, sizeof(resp));
  Osal_MemSet(&rq, 0, sizeof(rq));
  rq.ogf = 0x3f;
  rq.ocf = 0x02a;
  rq.rparam = &resp;
  rq.rlen = sizeof(resp);
  if (hci_send_req(&rq, FALSE) < 0)
    return BLE_STATUS_TIMEOUT;
  if (resp.Status) {
    return resp.Status;
  }
  *HW_Version = btoh(resp.HW_Version, 1);
  return BLE_STATUS_SUCCESS;
}
