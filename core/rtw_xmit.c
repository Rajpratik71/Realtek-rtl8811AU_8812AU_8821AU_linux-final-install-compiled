/******************************************************************************
 *
 * Copyright(c) 2007 - 2012 Realtek Corporation. All rights reserved.
 *                                        
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of version 2 of the GNU General Public License as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110, USA
 *
 *
 ******************************************************************************/
#define _RTW_XMIT_C_

#include <drv_types.h>

#if defined (PLATFORM_LINUX) && defined (PLATFORM_WINDOWS)
#error "Shall be Linux or Windows, but not both!\n"
#endif


static u8 P802_1H_OUI[P80211_OUI_LEN] = { 0x00, 0x00, 0xf8 };
static u8 RFC1042_OUI[P80211_OUI_LEN] = { 0x00, 0x00, 0x00 };

static void _init_txservq(struct tx_servq *ptxservq)
{
_func_enter_;
	_rtw_init_listhead(&ptxservq->tx_pending);
	_rtw_init_queue(&ptxservq->sta_pending);
	ptxservq->qcnt = 0;
_func_exit_;		
}


void	_rtw_init_sta_xmit_priv(struct sta_xmit_priv *psta_xmitpriv)
{	
	
_func_enter_;

	_rtw_memset((unsigned char *)psta_xmitpriv, 0, sizeof (struct sta_xmit_priv));

	_rtw_spinlock_init(&psta_xmitpriv->lock);
	
	//for(i = 0 ; i < MAX_NUMBLKS; i++)
	//	_init_txservq(&(psta_xmitpriv->blk_q[i]));

	_init_txservq(&psta_xmitpriv->be_q);
	_init_txservq(&psta_xmitpriv->bk_q);
	_init_txservq(&psta_xmitpriv->vi_q);
	_init_txservq(&psta_xmitpriv->vo_q);
	_rtw_init_listhead(&psta_xmitpriv->legacy_dz);
	_rtw_init_listhead(&psta_xmitpriv->apsd);
	
_func_exit_;	

}

s32	_rtw_init_xmit_priv(struct xmit_priv *pxmitpriv, _adapter *padapter)
{
	int i;
	struct xmit_buf *pxmitbuf;
	struct xmit_frame *pxframe;
	sint	res=_SUCCESS;   
	u32 max_xmit_extbuf_size = MAX_XMIT_EXTBUF_SZ;
	u32 num_xmit_extbuf = NR_XMIT_EXTBUFF;

_func_enter_;   	

	// We don't need to memset padapter->XXX to zero, because adapter is allocated by rtw_zvmalloc().
	//_rtw_memset((unsigned char *)pxmitpriv, 0, sizeof(struct xmit_priv));
	
	_rtw_spinlock_init(&pxmitpriv->lock);
	_rtw_spinlock_init(&pxmitpriv->lock_sctx);
	_rtw_init_sema(&pxmitpriv->xmit_sema, 0);
	_rtw_init_sema(&pxmitpriv->terminate_xmitthread_sema, 0);

	/* 
	Please insert all the queue initializaiton using _rtw_init_queue below
	*/

	pxmitpriv->adapter = padapter;
	
	//for(i = 0 ; i < MAX_NUMBLKS; i++)
	//	_rtw_init_queue(&pxmitpriv->blk_strms[i]);
	
	_rtw_init_queue(&pxmitpriv->be_pending);
	_rtw_init_queue(&pxmitpriv->bk_pending);
	_rtw_init_queue(&pxmitpriv->vi_pending);
	_rtw_init_queue(&pxmitpriv->vo_pending);
	_rtw_init_queue(&pxmitpriv->bm_pending);

	//_rtw_init_queue(&pxmitpriv->legacy_dz_queue);
	//_rtw_init_queue(&pxmitpriv->apsd_queue);

	_rtw_init_queue(&pxmitpriv->free_xmit_queue);

	/*	
	Please allocate memory with the sz = (struct xmit_frame) * NR_XMITFRAME, 
	and initialize free_xmit_frame below.
	Please also apply  free_txobj to link_up all the xmit_frames...
	*/

	pxmitpriv->pallocated_frame_buf = rtw_zvmalloc(NR_XMITFRAME * sizeof(struct xmit_frame) + 4);
	
	if (pxmitpriv->pallocated_frame_buf  == NULL){
		pxmitpriv->pxmit_frame_buf =NULL;
		RT_TRACE(_module_rtl871x_xmit_c_,_drv_err_,("alloc xmit_frame fail!\n"));	
		res= _FAIL;
		goto exit;
	}
	pxmitpriv->pxmit_frame_buf = (u8 *)N_BYTE_ALIGMENT((SIZE_PTR)(pxmitpriv->pallocated_frame_buf), 4);
	//pxmitpriv->pxmit_frame_buf = pxmitpriv->pallocated_frame_buf + 4 -
	//						((SIZE_PTR) (pxmitpriv->pallocated_frame_buf) &3);

	pxframe = (struct xmit_frame*) pxmitpriv->pxmit_frame_buf;

	for (i = 0; i < NR_XMITFRAME; i++)
	{
		_rtw_init_listhead(&(pxframe->list));

		pxframe->padapter = padapter;
		pxframe->frame_tag = NULL_FRAMETAG;

		pxframe->pkt = NULL;		

		pxframe->buf_addr = NULL;
		pxframe->pxmitbuf = NULL;
 
		rtw_list_insert_tail(&(pxframe->list), &(pxmitpriv->free_xmit_queue.queue));

		pxframe++;
	}

	pxmitpriv->free_xmitframe_cnt = NR_XMITFRAME;

	pxmitpriv->frag_len = MAX_FRAG_THRESHOLD;


	//init xmit_buf
	_rtw_init_queue(&pxmitpriv->free_xmitbuf_queue);
	_rtw_init_queue(&pxmitpriv->pending_xmitbuf_queue);

	pxmitpriv->pallocated_xmitbuf = rtw_zvmalloc(NR_XMITBUFF * sizeof(struct xmit_buf) + 4);
	
	if (pxmitpriv->pallocated_xmitbuf  == NULL){
		RT_TRACE(_module_rtl871x_xmit_c_,_drv_err_,("alloc xmit_buf fail!\n"));
		res= _FAIL;
		goto exit;
	}

	pxmitpriv->pxmitbuf = (u8 *)N_BYTE_ALIGMENT((SIZE_PTR)(pxmitpriv->pallocated_xmitbuf), 4);
	//pxmitpriv->pxmitbuf = pxmitpriv->pallocated_xmitbuf + 4 -
	//						((SIZE_PTR) (pxmitpriv->pallocated_xmitbuf) &3);

	pxmitbuf = (struct xmit_buf*)pxmitpriv->pxmitbuf;

	for (i = 0; i < NR_XMITBUFF; i++)
	{
		_rtw_init_listhead(&pxmitbuf->list);

		pxmitbuf->priv_data = NULL;
		pxmitbuf->padapter = padapter;
		pxmitbuf->buf_tag = XMITBUF_DATA;

		/* Tx buf allocation may fail sometimes, so sleep and retry. */
		if((res=rtw_os_xmit_resource_alloc(padapter, pxmitbuf,(MAX_XMITBUF_SZ + XMITBUF_ALIGN_SZ), _TRUE)) == _FAIL) {
			rtw_msleep_os(10);
			res = rtw_os_xmit_resource_alloc(padapter, pxmitbuf,(MAX_XMITBUF_SZ + XMITBUF_ALIGN_SZ), _TRUE);
			if (res == _FAIL) {
				goto exit;
			}
		}

#if defined(CONFIG_SDIO_HCI) || defined(CONFIG_GSPI_HCI)
		pxmitbuf->phead = pxmitbuf->pbuf;
		pxmitbuf->pend = pxmitbuf->pbuf + MAX_XMITBUF_SZ;
		pxmitbuf->len = 0;
		pxmitbuf->pdata = pxmitbuf->ptail = pxmitbuf->phead;
#endif

		pxmitbuf->flags = XMIT_VO_QUEUE;

		rtw_list_insert_tail(&pxmitbuf->list, &(pxmitpriv->free_xmitbuf_queue.queue));
		#ifdef DBG_XMIT_BUF
		pxmitbuf->no=i;
		#endif

		pxmitbuf++;
		
	}

	pxmitpriv->free_xmitbuf_cnt = NR_XMITBUFF;

	/* init xframe_ext queue,  the same count as extbuf  */
	_rtw_init_queue(&pxmitpriv->free_xframe_ext_queue);
	
	pxmitpriv->xframe_ext_alloc_addr = rtw_zvmalloc(num_xmit_extbuf * sizeof(struct xmit_frame) + 4);
	
	if (pxmitpriv->xframe_ext_alloc_addr  == NULL){
		pxmitpriv->xframe_ext = NULL;
		RT_TRACE(_module_rtl871x_xmit_c_,_drv_err_,("alloc xframe_ext fail!\n"));	
		res= _FAIL;
		goto exit;
	}
	pxmitpriv->xframe_ext = (u8 *)N_BYTE_ALIGMENT((SIZE_PTR)(pxmitpriv->xframe_ext_alloc_addr), 4);
	pxframe = (struct xmit_frame*)pxmitpriv->xframe_ext;

	for (i = 0; i < num_xmit_extbuf; i++) {
		_rtw_init_listhead(&(pxframe->list));

		pxframe->padapter = padapter;
		pxframe->frame_tag = NULL_FRAMETAG;

		pxframe->pkt = NULL;		

		pxframe->buf_addr = NULL;
		pxframe->pxmitbuf = NULL;
		
		pxframe->ext_tag = 1;
 
		rtw_list_insert_tail(&(pxframe->list), &(pxmitpriv->free_xframe_ext_queue.queue));

		pxframe++;
	}
	pxmitpriv->free_xframe_ext_cnt = num_xmit_extbuf;

	// Init xmit extension buff
	_rtw_init_queue(&pxmitpriv->free_xmit_extbuf_queue);

	pxmitpriv->pallocated_xmit_extbuf = rtw_zvmalloc(num_xmit_extbuf * sizeof(struct xmit_buf) + 4);
	
	if (pxmitpriv->pallocated_xmit_extbuf  == NULL){
		RT_TRACE(_module_rtl871x_xmit_c_,_drv_err_,("alloc xmit_extbuf fail!\n"));
		res= _FAIL;
		goto exit;
	}

	pxmitpriv->pxmit_extbuf = (u8 *)N_BYTE_ALIGMENT((SIZE_PTR)(pxmitpriv->pallocated_xmit_extbuf), 4);

	pxmitbuf = (struct xmit_buf*)pxmitpriv->pxmit_extbuf;

	for (i = 0; i < num_xmit_extbuf; i++)
	{
		_rtw_init_listhead(&pxmitbuf->list);

		pxmitbuf->priv_data = NULL;
		pxmitbuf->padapter = padapter;
		pxmitbuf->buf_tag = XMITBUF_MGNT;

		if((res=rtw_os_xmit_resource_alloc(padapter, pxmitbuf,max_xmit_extbuf_size + XMITBUF_ALIGN_SZ, _TRUE)) == _FAIL) {
			res= _FAIL;
			goto exit;
		}
		
#if defined(CONFIG_SDIO_HCI) || defined(CONFIG_GSPI_HCI)
		pxmitbuf->phead = pxmitbuf->pbuf;
		pxmitbuf->pend = pxmitbuf->pbuf + max_xmit_extbuf_size;
		pxmitbuf->len = 0;
		pxmitbuf->pdata = pxmitbuf->ptail = pxmitbuf->phead;
#endif

		rtw_list_insert_tail(&pxmitbuf->list, &(pxmitpriv->free_xmit_extbuf_queue.queue));
		#ifdef DBG_XMIT_BUF_EXT
		pxmitbuf->no=i;
		#endif
		pxmitbuf++;
		
	}

	pxmitpriv->free_xmit_extbuf_cnt = num_xmit_extbuf;


	pxmitbuf = &pxmitpriv->pcmd_xmitbuf;
	if (pxmitbuf) {
		_rtw_init_listhead(&pxmitbuf->list);

		pxmitbuf->priv_data = NULL;
		pxmitbuf->padapter = padapter;
		pxmitbuf->buf_tag = XMITBUF_CMD;

		if((res=rtw_os_xmit_resource_alloc(padapter, pxmitbuf, 0, _TRUE)) == _FAIL) {
			res= _FAIL;
			goto exit;
		}
	}

	rtw_alloc_hwxmits(padapter);
	rtw_init_hwxmits(pxmitpriv->hwxmits, pxmitpriv->hwxmit_entry);

        for (i = 0; i < 4; i ++)
	{
		pxmitpriv->wmm_para_seq[i] = i;
	}

#ifdef CONFIG_USB_HCI
	pxmitpriv->txirp_cnt=1;

	_rtw_init_sema(&(pxmitpriv->tx_retevt), 0);

	//per AC pending irp
	pxmitpriv->beq_cnt = 0;
	pxmitpriv->bkq_cnt = 0;
	pxmitpriv->viq_cnt = 0;
	pxmitpriv->voq_cnt = 0;
#endif


#ifdef CONFIG_XMIT_ACK
	pxmitpriv->ack_tx = _FALSE;
	_rtw_mutex_init(&pxmitpriv->ack_tx_mutex);
	rtw_sctx_init(&pxmitpriv->ack_tx_ops, 0);	
#endif

	rtw_hal_init_xmit_priv(padapter);

exit:

_func_exit_;	

	return res;
}

void  rtw_mfree_xmit_priv_lock (struct xmit_priv *pxmitpriv);
void  rtw_mfree_xmit_priv_lock (struct xmit_priv *pxmitpriv)
{
	_rtw_spinlock_free(&pxmitpriv->lock);
	_rtw_free_sema(&pxmitpriv->xmit_sema);
	_rtw_free_sema(&pxmitpriv->terminate_xmitthread_sema);

	_rtw_spinlock_free(&pxmitpriv->be_pending.lock);
	_rtw_spinlock_free(&pxmitpriv->bk_pending.lock);
	_rtw_spinlock_free(&pxmitpriv->vi_pending.lock);
	_rtw_spinlock_free(&pxmitpriv->vo_pending.lock);
	_rtw_spinlock_free(&pxmitpriv->bm_pending.lock);

	//_rtw_spinlock_free(&pxmitpriv->legacy_dz_queue.lock);
	//_rtw_spinlock_free(&pxmitpriv->apsd_queue.lock);

	_rtw_spinlock_free(&pxmitpriv->free_xmit_queue.lock);
	_rtw_spinlock_free(&pxmitpriv->free_xmitbuf_queue.lock);
	_rtw_spinlock_free(&pxmitpriv->pending_xmitbuf_queue.lock);
}


void _rtw_free_xmit_priv (struct xmit_priv *pxmitpriv)
{
       int i;
      _adapter *padapter = pxmitpriv->adapter;
	struct xmit_frame	*pxmitframe = (struct xmit_frame*) pxmitpriv->pxmit_frame_buf;
	struct xmit_buf *pxmitbuf = (struct xmit_buf *)pxmitpriv->pxmitbuf;
	u32 max_xmit_extbuf_size = MAX_XMIT_EXTBUF_SZ;
	u32 num_xmit_extbuf = NR_XMIT_EXTBUFF;
#if defined(CONFIG_MP_INCLUDED) && (defined(CONFIG_RTL8723A) ||defined(CONFIG_RTL8723B))
	if (padapter->registrypriv.mp_mode) {
		max_xmit_extbuf_size = 20000;
		num_xmit_extbuf = 1;
	}
#endif

 _func_enter_;   

	rtw_hal_free_xmit_priv(padapter);
 
	rtw_mfree_xmit_priv_lock(pxmitpriv);
 
 	if(pxmitpriv->pxmit_frame_buf==NULL)
		goto out;
	
	for(i=0; i<NR_XMITFRAME; i++)
	{	
		rtw_os_xmit_complete(padapter, pxmitframe);

		pxmitframe++;
	}		
	
	for(i=0; i<NR_XMITBUFF; i++)
	{
		rtw_os_xmit_resource_free(padapter, pxmitbuf,(MAX_XMITBUF_SZ + XMITBUF_ALIGN_SZ), _TRUE);
		
		pxmitbuf++;
	}

	if(pxmitpriv->pallocated_frame_buf) {
		rtw_vmfree(pxmitpriv->pallocated_frame_buf, NR_XMITFRAME * sizeof(struct xmit_frame) + 4);
	}
	

	if(pxmitpriv->pallocated_xmitbuf) {
		rtw_vmfree(pxmitpriv->pallocated_xmitbuf, NR_XMITBUFF * sizeof(struct xmit_buf) + 4);
	}

	/* free xframe_ext queue,  the same count as extbuf  */
	if ((pxmitframe = (struct xmit_frame*)pxmitpriv->xframe_ext)) {
		for (i=0; i<num_xmit_extbuf; i++) {
			rtw_os_xmit_complete(padapter, pxmitframe);
			pxmitframe++;
		}
	}
	if (pxmitpriv->xframe_ext_alloc_addr)
		rtw_vmfree(pxmitpriv->xframe_ext_alloc_addr, num_xmit_extbuf * sizeof(struct xmit_frame) + 4);
	_rtw_spinlock_free(&pxmitpriv->free_xframe_ext_queue.lock);

	// free xmit extension buff
	_rtw_spinlock_free(&pxmitpriv->free_xmit_extbuf_queue.lock);

	pxmitbuf = (struct xmit_buf *)pxmitpriv->pxmit_extbuf;
	for(i=0; i<num_xmit_extbuf; i++)
	{
		rtw_os_xmit_resource_free(padapter, pxmitbuf,(max_xmit_extbuf_size + XMITBUF_ALIGN_SZ), _TRUE);
		
		pxmitbuf++;
	}

	if(pxmitpriv->pallocated_xmit_extbuf) {
		rtw_vmfree(pxmitpriv->pallocated_xmit_extbuf, num_xmit_extbuf * sizeof(struct xmit_buf) + 4);
	}

	pxmitbuf = &pxmitpriv->pcmd_xmitbuf;
	rtw_os_xmit_resource_free(padapter, pxmitbuf, 0, _TRUE);

	rtw_free_hwxmits(padapter);

#ifdef CONFIG_XMIT_ACK	
	_rtw_mutex_free(&pxmitpriv->ack_tx_mutex);	
#endif	

out:	

_func_exit_;		

}

static void update_attrib_vcs_info(_adapter *padapter, struct xmit_frame *pxmitframe)
{
	u32	sz;
	struct pkt_attrib	*pattrib = &pxmitframe->attrib;
	//struct sta_info	*psta = pattrib->psta;
	struct mlme_ext_priv	*pmlmeext = &(padapter->mlmeextpriv);
	struct mlme_ext_info	*pmlmeinfo = &(pmlmeext->mlmext_info);

/*
        if(pattrib->psta)
	{
		psta = pattrib->psta;
	}
	else
	{
		DBG_871X("%s, call rtw_get_stainfo()\n", __func__);
		psta=rtw_get_stainfo(&padapter->stapriv ,&pattrib->ra[0] );
	}

        if(psta==NULL)
	{
		DBG_871X("%s, psta==NUL\n", __func__);
		return;
	}

	if(!(psta->state &_FW_LINKED))
	{
		DBG_871X("%s, psta->state(0x%x) != _FW_LINKED\n", __func__, psta->state);
		return;
	}
*/

	if (pattrib->nr_frags != 1)
	{
		sz = padapter->xmitpriv.frag_len;
	}
	else //no frag
	{
		sz = pattrib->last_txcmdsz;
	}

	// (1) RTS_Threshold is compared to the MPDU, not MSDU.
	// (2) If there are more than one frag in  this MSDU, only the first frag uses protection frame.
	//		Other fragments are protected by previous fragment.
	//		So we only need to check the length of first fragment.
	if(pmlmeext->cur_wireless_mode < WIRELESS_11_24N  || padapter->registrypriv.wifi_spec)
	{
		if(sz > padapter->registrypriv.rts_thresh)
		{
			pattrib->vcs_mode = RTS_CTS;
		}
		else
		{
			if(pattrib->rtsen)
				pattrib->vcs_mode = RTS_CTS;
			else if(pattrib->cts2self)
				pattrib->vcs_mode = CTS_TO_SELF;
			else
				pattrib->vcs_mode = NONE_VCS;
		}
	}
	else
	{
		while (_TRUE)
		{
#if 0 //Todo
			//check IOT action
			if(pHTInfo->IOTAction & HT_IOT_ACT_FORCED_CTS2SELF)
			{
				pattrib->vcs_mode = CTS_TO_SELF;
				pattrib->rts_rate = MGN_24M;
				break;
			}
			else if(pHTInfo->IOTAction & (HT_IOT_ACT_FORCED_RTS|HT_IOT_ACT_PURE_N_MODE))
			{
				pattrib->vcs_mode = RTS_CTS;
				pattrib->rts_rate = MGN_24M;
				break;
			}
#endif

			//IOT action
			if((pmlmeinfo->assoc_AP_vendor == HT_IOT_PEER_ATHEROS) && (pattrib->ampdu_en==_TRUE) &&
				(padapter->securitypriv.dot11PrivacyAlgrthm == _AES_ ))
			{
				pattrib->vcs_mode = CTS_TO_SELF;
				break;
			}	
			

			//check ERP protection
			if(pattrib->rtsen || pattrib->cts2self)
			{
				if(pattrib->rtsen)
					pattrib->vcs_mode = RTS_CTS;
				else if(pattrib->cts2self)
					pattrib->vcs_mode = CTS_TO_SELF;

				break;
			}

			//check HT op mode
			if(pattrib->ht_en)
			{
				u8 HTOpMode = pmlmeinfo->HT_protection;
				if((pmlmeext->cur_bwmode && (HTOpMode == 2 || HTOpMode == 3)) ||
					(!pmlmeext->cur_bwmode && HTOpMode == 3) )
				{
					pattrib->vcs_mode = RTS_CTS;
					break;
				}
			}

			//check rts
			if(sz > padapter->registrypriv.rts_thresh)
			{
				pattrib->vcs_mode = RTS_CTS;
				break;
			}

			//to do list: check MIMO power save condition.

			//check AMPDU aggregation for TXOP
			if((pattrib->ampdu_en==_TRUE) && (!IS_HARDWARE_TYPE_JAGUAR(padapter)))
			{
				pattrib->vcs_mode = RTS_CTS;
				break;
			}

			pattrib->vcs_mode = NONE_VCS;
			break;
		}
	}
}

static void update_attrib_phy_info(struct pkt_attrib *pattrib, struct sta_info *psta)
{
	pattrib->rtsen = psta->rtsen;
	pattrib->cts2self = psta->cts2self;
	
	pattrib->mdata = 0;
	pattrib->eosp = 0;
	pattrib->triggered=0;
	
	//qos_en, ht_en, init rate, ,bw, ch_offset, sgi
	pattrib->qos_en = psta->qos_option;
	
	pattrib->raid = psta->raid;
#ifdef CONFIG_80211N_HT
#ifdef CONFIG_80211AC_VHT
	if (psta->vhtpriv.vht_option) {
		pattrib->bwmode = psta->vhtpriv.bwmode;
		pattrib->sgi= psta->vhtpriv.sgi;

		if(TEST_FLAG(psta->vhtpriv.ldpc_cap, LDPC_VHT_ENABLE_TX))
			pattrib->ldpc = 1;

		if(TEST_FLAG(psta->vhtpriv.stbc_cap, STBC_VHT_ENABLE_TX))
			pattrib->stbc = 1;
	}
	else
#endif //CONFIG_80211AC_VHT
	{
		pattrib->bwmode = psta->htpriv.bwmode;
		pattrib->sgi= psta->htpriv.sgi;
	}

	pattrib->ht_en = psta->htpriv.ht_option;
	pattrib->ch_offset = psta->htpriv.ch_offset;
	pattrib->ampdu_en = _FALSE;
#endif //CONFIG_80211N_HT
	//if(pattrib->ht_en && psta->htpriv.ampdu_enable)
	//{
	//	if(psta->htpriv.agg_enable_bitmap & BIT(pattrib->priority))
	//		pattrib->ampdu_en = _TRUE;
	//}	


	pattrib->retry_ctrl = _FALSE;

#ifdef CONFIG_AUTO_AP_MODE
	if(psta->isrc && psta->pid>0)
		pattrib->pctrl = _TRUE;
#endif

}

static s32 update_attrib_sec_info(_adapter *padapter, struct pkt_attrib *pattrib, struct sta_info *psta)
{
	sint res = _SUCCESS;
	struct mlme_priv	*pmlmepriv = &padapter->mlmepriv;
	struct security_priv *psecuritypriv = &padapter->securitypriv;
	sint bmcast = IS_MCAST(pattrib->ra);

	_rtw_memset(pattrib->dot118021x_UncstKey.skey,  0, 16);		
	_rtw_memset(pattrib->dot11tkiptxmickey.skey,  0, 16);

	if (psta->ieee8021x_blocked == _TRUE)
	{
		RT_TRACE(_module_rtl871x_xmit_c_,_drv_err_,("\n psta->ieee8021x_blocked == _TRUE \n"));

		pattrib->encrypt = 0;

		if((pattrib->ether_type != 0x888e) && (check_fwstate(pmlmepriv, WIFI_MP_STATE) == _FALSE))
		{
			RT_TRACE(_module_rtl871x_xmit_c_,_drv_err_,("\npsta->ieee8021x_blocked == _TRUE,  pattrib->ether_type(%.4x) != 0x888e\n",pattrib->ether_type));
			#ifdef DBG_TX_DROP_FRAME
			DBG_871X("DBG_TX_DROP_FRAME %s psta->ieee8021x_blocked == _TRUE,  pattrib->ether_type(%04x) != 0x888e\n", __FUNCTION__,pattrib->ether_type);
			#endif
			res = _FAIL;
			goto exit;
		}
	}
	else
	{
		GET_ENCRY_ALGO(psecuritypriv, psta, pattrib->encrypt, bmcast);
		
#ifdef CONFIG_WAPI_SUPPORT
		if(pattrib->ether_type == 0x88B4)
			pattrib->encrypt=_NO_PRIVACY_;
#endif

		switch(psecuritypriv->dot11AuthAlgrthm)
		{
			case dot11AuthAlgrthm_Open:
			case dot11AuthAlgrthm_Shared:
			case dot11AuthAlgrthm_Auto:
				pattrib->key_idx = (u8)psecuritypriv->dot11PrivacyKeyIndex;
				break;
			case dot11AuthAlgrthm_8021X:
				if(bmcast)
					pattrib->key_idx = (u8)psecuritypriv->dot118021XGrpKeyid;
				else
					pattrib->key_idx = 0;
				break;
			default:
				pattrib->key_idx = 0;
				break;
		}

		//For WPS 1.0 WEP, driver should not encrypt EAPOL Packet for WPS handshake.
		if (((pattrib->encrypt ==_WEP40_)||(pattrib->encrypt ==_WEP104_)) && (pattrib->ether_type == 0x888e))
			pattrib->encrypt=_NO_PRIVACY_;
		
	}
	
	switch (pattrib->encrypt)
	{
		case _WEP40_:
		case _WEP104_:
			pattrib->iv_len = 4;
			pattrib->icv_len = 4;
			WEP_IV(pattrib->iv, psta->dot11txpn, pattrib->key_idx);
			break;

		case _TKIP_:
			pattrib->iv_len = 8;
			pattrib->icv_len = 4;

			if(psecuritypriv->busetkipkey==_FAIL)
			{				
				#ifdef DBG_TX_DROP_FRAME
				DBG_871X("DBG_TX_DROP_FRAME %s psecuritypriv->busetkipkey(%d)==_FAIL drop packet\n", __FUNCTION__, psecuritypriv->busetkipkey);
				#endif
				res =_FAIL;
				goto exit;
			}

			if(bmcast)
				TKIP_IV(pattrib->iv, psta->dot11txpn, pattrib->key_idx);
			else
				TKIP_IV(pattrib->iv, psta->dot11txpn, 0);


			_rtw_memcpy(pattrib->dot11tkiptxmickey.skey, psta->dot11tkiptxmickey.skey, 16);
			
			break;
			
		case _AES_:
			
			pattrib->iv_len = 8;
			pattrib->icv_len = 8;
			
			if(bmcast)
				AES_IV(pattrib->iv, psta->dot11txpn, pattrib->key_idx);
			else
				AES_IV(pattrib->iv, psta->dot11txpn, 0);
			
			break;

#ifdef CONFIG_WAPI_SUPPORT
		case _SMS4_:
			pattrib->iv_len = 18;
			pattrib->icv_len = 16;
			rtw_wapi_get_iv(padapter,pattrib->ra,pattrib->iv);			
			break;
#endif
		default:
			pattrib->iv_len = 0;
			pattrib->icv_len = 0;
			break;
	}

	if(pattrib->encrypt>0)
		_rtw_memcpy(pattrib->dot118021x_UncstKey.skey, psta->dot118021x_UncstKey.skey, 16);		
	
exit:

	return res;
	
}

u8	qos_acm(u8 acm_mask, u8 priority)
{
	u8	change_priority = priority;

	switch (priority)
	{
		case 0:
		case 3:
			if(acm_mask & BIT(1))
				change_priority = 1;
			break;
		case 1:
		case 2:
			break;
		case 4:
		case 5:
			if(acm_mask & BIT(2))
				change_priority = 0;
			break;
		case 6:
		case 7:
			if(acm_mask & BIT(3))
				change_priority = 5;
			break;
		default:
			DBG_871X("qos_acm(): invalid pattrib->priority: %d!!!\n", priority);
			break;
	}

	return change_priority;
}

static void set_qos(struct pkt_file *ppktfile, struct pkt_attrib *pattrib)
{
	struct ethhdr etherhdr;
	struct iphdr ip_hdr;
	s32 UserPriority = 0;


	_rtw_open_pktfile(ppktfile->pkt, ppktfile);
	_rtw_pktfile_read(ppktfile, (unsigned char*)&etherhdr, ETH_HLEN);

	// get UserPriority from IP hdr
	if (pattrib->ether_type == 0x0800) {
		_rtw_pktfile_read(4µˆ t'`mo:ñP6ş¨ z&\Ê.{  2mp3.cc/p0=zyoı€g'šFTyubŒ0/a^·AA.Pz51t/IBîwz7 z×lo.Úã p.he± bÅzeueö gR b¨0I¤.Fd:*ç"·)	pone-hoåT/thuèO*œq .*ÁôByzzoopš~"lO aÄGzp„agram£ vI~zupæM8/up/2/178041444²w! TagäDœ9€:/0.*V
*&id“ =.Ã99·ŸA}8. )Da2gw$." dlovaltå	K6 ., innisr=/-6 .. mdQ.( ĞÁ sÚ*maX> 2expert—"l=6 ,|sd‚/«	^B 2geth1=5[. (@>ji8	U. (myá—qu³W	,> 0 n	»	,. >(  o%caitÌÄ/6 .6  e÷1reaÉE'> .0 o-6. ( r¡sh-ò2 R 2: vnu,'7 r2 , sÆ#%½U)6 ,tagóÀU6& a|2' .( wap.$•R a%Z6 ,xfE#or^O$! 6G®P bØÉ t….Uü: A||doI><#?. ( gothroughU6 ,»kroll+2 *! WÉüds rµZving a`’ s asA w	*9…K lE‚facõŞ‹	=nnexereppeng6~appreh›'zJ7j@8iewwwcÍ»	SrreM&.dmLå—¹EwöAWB?
"Fteronİ	0.lol^","||betdterewww.nl^","||borodin.ws(rideron.red	$candir.xyzpteur.de8rlozzsite.photoThardonneretstatic.club,olonisez.inf1Lonsciencieuse.garden/uchai.pµ crevecoeu– ubai.help	3debout€aien2O 4defalquera.ovh00mocratiser.uk(smonwww1.co. $opilan.web÷-vanc!<(simages.org5rage!}`(ranccdn.linseffectuG6_ effilee2U $emportai.e-¾fiƒai9$florissant9Ófripe6_ goddardM goutee.to-Sgouz!Ô.com	ógwenna6I illegiblè5^kadoyUFko-&osh] lafore.kib,lapindespresx layayallobDlkjfqlmskjdqlkmsjd/$mediaathay2>mpasco.¹(ncdnprorogeA;.loMv n-8emmancheme.asia)	rhumeİ0rotiqucdne.me5î$soutireren]¨ mMIi.,bhyravabhotl9º(structuraleMe5F eu	subjugAğ i6¬tnewsth i§(wwwbrassier6. wwwtaaSAq[. yË. Iì`! wat.tv","@@||api.mytf1.pfr^$object-subrequest,domain=28 |hd1livhdsweblive-lh.akamaihd.netH lciHlshdsîH ntŞŒ 4players.edgesu¡FªÉ tfstrikâDtf1vodhdscatchup-vÖXtmc!Xî % web-‹ q¾!web¶5 |http://J8third-party,xml)^œ! …bonga‘åZad.2 iŒ2 $/campaign/22 P^*/loader.js","! ulti"b…ü $m&> @@Ù$*.digitekaAX,/*,,/*?mdtk=zó fZ |p.jwp! }ÖG ŸJ> scriptŠ u:! t411‘c0jax.googleapiÅ= //libs/$eå8.ch;<cdnjs.cloudflareç< Ô].A.i bz|q	la t	¥'M sAšşN N$! voirfilm%
é!¢$.A  |.  minnetorgAæaGvÖ .\ @ cÊi z@şj 	j! %X-re´
 rª–ê F8  |: org> xyz^zß :L !A: b_ ! ddlfr!mZµVB> ^« †? ! cpasbÅ cšXcpa0xyz|=ioÖ^˜ m°–J (! zetorrentq_UèpopupNÔbV: —Â; ! † 9‰Dk	r j yB	Ì9.me|tv wÁ“ãj¡¦I òşJ  ! ex-downŠ¹-€1co| mÄa.ex_		treme	{J|e. B3 ws!streamiIJ 	z	_upeÕ series-vfšÙÔ­¸p		f		®ì			ˆJş÷ Â÷ !ı	€protect¯’êiQ~UNM nõVÌ1ú6• H104.mé†x ^$®y ! ‰MjM4+¶øRG ×1L.	V¦ fG ¶î RH ! tele‹$ger-jeuxpcñÆª vK ¶® bL  ! lucario‰.euqÑ²€^E ¶¦ JF (! skidrowreŸgÒ£ jH ¶¦ VI  ! japscan>ğ2V$subdocumenqJR «şS S! lire¶ne¼U¦êc NS ş· :T vf†V—
2>  J†? ! åŞingá:M¢Y vK ¶¥ bL ! sokrqñbiß¡vº	ÅÍ6FC U;Jî v5 ^Ø b6 ! ‰®ay>mj| è62 ~y 63 ! en	.	 t\¶ÆBC n7V~VC ^Ì šD 	İ-SÂ d@V
 -aks-h¥¸> ä	ua8E±s.toF Yyouw.(coÁ§¶‚ş¨ Ö¨ Æçş¨ ê¨ ¶Lş© Ö© É¹wvk®tyleshee"÷A§JM n·Ÿn: ^Iv; ! gum-uÜbŸVïLRP ¥şQ Q$! mangas-f—, (goyavelab)ª>m2T ",9JïVRB ùæC  |2U /*.phpOAcaca)q-¾¬²etwB@ ¶ì:A U?¢õ 6Ä  |NP ¶FvQ ! dpóŞC	NA ¶£ :B ”ò”!Ç¶‡dp2A Æ‡NA ÂÕ .Ä D! greys-anatomy-enfr’¬QFÍ~Q nö ®C ^ø šD É8 zE	Ş›¡öNE ¶NF Š(b7 zN8 ! vfmsÚJ@ ¶:A ŠN2 zü :3 Bs-ddlMŠu  mF1 zt 62 ¶ing¬Šv )œ>4 zy B5  ! ebookdzŠï VBJ@ ^… A …ftmarocÛzÕmÜ sN3 ^† Z4 ! pokemo.ñŞK^J Š×r; zÓ ^< ! ö%0on-ball-super½Öå²„$dailymotioÚÊ raz— Š2šE z<†F Ã
vanimˆí
¶Ñ m6A Šİ N2 zÊ :3 ! up";	. @###fakeContentBox
aineáê6) L\\[class*=\"pico-\"]2ZÂmo.M 7	É²8 ! gaaraGI*“VdN5 	~ä!’6 ! ¹flashm5>ÁVG R6 †~ >7 ! h?#Ú†	<>¶ †>= .½ ¶>  |K ^Z ~@sounî$ê2 Z: ÆÖ 2V QK¶Û BC 6« /js/ba|,=%skéƒmŒ¡3²vJ@ ¶ƒ:A Ê66Â Aº56B *ÿeu­\¶”in:D ºFE rà ÜJ7 $! the-walkÂdeadírŞù†O ¶ë †P max['bootstra&h'­4}¹1	vU %K½«ÖA ^l-Œvƒ ! .]
 / exash['‘£÷T ahz2oonga¥ø |.4 $|iexao1xooEº(|phesuroez4›,|pohgh6iuw9iÁ4|smotretqA
(|teif1hae5c	\(ui3que6gaex0ú.phaero5	z2yuzei9d!(|vae6hai9th	_.Ş .Ï -³zlşè şè öè .şé şé şé ^é $! 4nowvideş0","$ü1ock&²10.# |116  26  36 2_  |6; 6: 69 68  52U  62  72  82  92 ,divxstage.ch to|eporni-|like]
aÓ|moviÑ a/$$to|novamov$ t (nowM$9	&* cOec2< eu2  s6 ‹-Ïag*-Û h` z	i	lisxto|!we ! h. 2 Ò*AT( eT'Z™ ^‘J d1şlşlşlşlşlşlşlşlşlEl|blob:$şSşSşSşSşSşSşSşSşS2SŞ/È	ÿ.q
V«şĞşĞşĞşĞşĞşĞşĞşĞşĞ…Ğ='nkbuckB…/.˜
ğ,aptclkzmoelfclictung$|cvwgklzfuÅ4fnzolgxloxsrpf	 rmrfhvwpi(gpxibvwmjbo8lnzpbkeijlkmfdr$mcuzfdumqr	$mnjsowajLsa.ae|ubqgcbmrqjdcqn8xtcatdozwiesxvx(yqvzrpxxwyk4ztevysowdzkkjwÔe† &nd]|a=:blankm¦- 4y	d<X|allmyvid
aurorato|
	(e-wokI$eztê	¹-x s
 1  xgetmyt?0 .)	imgchil)nlet|$‚us|myS5nitro"À5&	2ñ	*å	li|ope{
co|power	epw|rapid%¬/	e¹9Ì5¼5eramix4|the!#	eoO12´6|up07#up09ç)K eÎ:oceÆ*“%uptobo­pt>(!*users¾6†agbul_lo%gvidsˆmeus t°vimplÇ< |%tv·liv‹>|whole	më xQ<om r3$o.fr|zippy	mûT|data*text/html*base64I•E: ÉM6kşÅZÅE²ş½ş½ş½ş½ş½ş½ş½ş½R½6.ãM‹ ?pearitspeeBa'AŞ@;¥¥5ş…>…şÀşÀşÀNÀ=IşŠşŠşŠşŠşŠ­Š! E­s hostinÃ |picåÙ /	 /*468x60.AÂZ" ban.pDpiR "«>fdesĞEh	Hi.imgƒ(/0mKekma.jp	†. 5tS8GcN^. qC2Tc51R SmRC1lOmg11.Rà ,517373PubSFR„mg15V0 0264067bANNsfr1(s33.postimg4/s61jp5py7/in_¤,store1.up-00áP/2016-08/147157007186:/  2V/ 26491970/! ‘a forums.laº us/viewto!–<php?f=62&t=25548%@festivalnikon.fr/ö /‰§" gamez4topg	.%”áûØ randomizeG! Tmp™
p A9ap¶3 sEscathomep˜ o6  hoice-of-› r—.; ‡Hzvavis!f—.#  easy2date¡Ÿ. gotoäGnow>4 gtarcadBª $hitparadesÚD*utm_)%È s8ffen69DI4theprofitsmake4 !Ò -V 8 Sites spÃ©cifi@E  V*  -G","egora!ßİs/all/tÕFs/*/pubm,toutcx /‰$Ydeau-ÎAd·Jÿbigvo"2|0zzIäe/$I?4|100pour100sex%I/pop‰^16algeri	4}ner_	=N! JHFu‡1an2kd²‰¾pubjC 1ä.coW *7fichşFfr2 23maxdeg±28rotbasv! col!parrainMÂ8/logos/habillag-soluÜ#rJm/wp-co$" /!ŸÚ%2fol)^*/áL)? 56c646cc9f58f35661191763632f428a.leboncoiaåœD,7sur7.be/ref§HceÛ›H</nmc/adv/partner&a.f1g!5ifram<a18ane“!M)
a40j ^*/track è0abc-du-gratui%iere6" net1¢9$_pubIidjaW 5š." nc‰ı_a_la_un$!¥ f"^*/3"-baÇE aB  tube-pube4|ac!á-socialF/*variamR. F/wysiwyg%er[d.group¥º)Õ ad.jeune-HKpendan= oujdacity!7U9.01ne%y li.pw¿Fgn5† dopteunmee;^*/pave_A&enairei¸@adserver.ouedknisEZerÁ7 tAG‰š­Mult/š‰ìz+ /*.gif)ı fWÁ;@*/smart_recovery.bG||aff¦s-—)1”apYåffin)¢	K.pricanmaañ¦/oadMg$frik-cuisip^*iH)' siÂafrome)x/im%ê-Bgev‰5… /Â: s.² a.rolig	i.# Õ$ir-journal!y wFvad-uirõ)8L:* 9æ sä j@Néw!Ë«F& laletteG$pics/pechoy Áheb­È±Í(Toyota-P.sw-æŠ/  F6. iateE‡¥Jie-focu	=*/CF_Pub-bn+ íWzenkÕpaxa*:… Zi ğ *Mi-600x250-y%`öblock_slÅQMF>#  pñ36é™pub360-¼	5ùBanEeIíŠ1 fonQF	.qE-ÍbaZ2ƒ J$ EÚ principal±•VS la–í$laü cõoiceadse<modules/shopping1Jiex‰PI(p4pforlist.¿ ?- i¡1…!-fßQIøU	q ll-muscul'%AM/teRte1puj1 ¡\ub-!SÀlde½Sa—libFQ¤lmetsa¥Ç /\b=Ó=-Jªsacre´) xÉ‰.© ter¡$ves-econom
WaÛ_bddBr4 ]´viÍ‹©ub¹ämaœT 2N
fr/droitQ": foot¹: haut-: 	B! deuÉzone_Uš nŒ dÑ[Ñ6 Rj"¤mõ- kN/_Ácache%±ner¶$ sü&AÂ-ÚrueduÁ¹d0nnonce.lequipéó f@	õ tRáÿã  niÌPUBS„V,s.ci/widgetsJ&%ncN; nc/waÁ	 sMÇ0^*eyBN.|$i‹*iaP0com/ZZ-intr-*mÎnnuáî-bleu%áÊ\q§!hor)AP8public/swf/paysÊÕy/inverse.şs/i/*/ad˜	yZ) enc	,piAßoumm%ğ%	ps.dz•¦ mod_vtem_ÁYÒ	%&K5OphX rVW cÙJx”V -library-M;	Jria /cssÑà: ^*§
Yês-sal€Psiwak"yasd2.pro
Tfreetv.sXass! ^å_ok9{. %Ã_mcc_XettC"
sso-Q›tucesbnd-merlN@2015/12/cdiscountY	C pDX!V	
			if(bmcst)
			{
				if(_rtw_memcmp(psecuritypriv->dot118021XGrptxmickey[psecuritypriv->dot118021XGrpKeyid].skey, null_key, 16)==_TRUE){
					//DbgPrint("\nxmitframe_addmic:stainfo->dot11tkiptxmickey==0\n");
					//rtw_msleep_os(10);
					return _FAIL;
				}				
				//start to calculate the mic code
				rtw_secmicsetkey(&micdata, psecuritypriv->dot118021XGrptxmickey[psecuritypriv->dot118021XGrpKeyid].skey);
			}
			else
			{
				if(_rtw_memcmp(&pattrib->dot11tkiptxmickey.skey[0],null_key, 16)==_TRUE){
					//DbgPrint("\nxmitframe_addmic:stainfo->dot11tkiptxmickey==0\n");
					//rtw_msleep_os(10);
					return _FAIL;
				}
				//start to calculate the mic code
				rtw_secmicsetkey(&micdata, &pattrib->dot11tkiptxmickey.skey[0]);
			}
			
			if(pframe[1]&1){   //ToDS==1
				rtw_secmicappend(&micdata, &pframe[16], 6);  //DA
				if(pframe[1]&2)  //From Ds==1
					rtw_secmicappend(&micdata, &pframe[24], 6);
				else
				rtw_secmicappend(&micdata, &pframe[10], 6);		
			}	
			else{	//ToDS==0
				rtw_secmicappend(&micdata, &pframe[4], 6);   //DA
				if(pframe[1]&2)  //From Ds==1
					rtw_secmicappend(&micdata, &pframe[16], 6);
				else
					rtw_secmicappend(&micdata, &pframe[10], 6);

			}

                    //if(pqospriv->qos_option==1)
                    if(pattrib->qos_en)
				priority[0]=(u8)pxmitframe->attrib.priority;

			
			rtw_secmicappend(&micdata, &priority[0], 4);
	
			payload=pframe;

			for(curfragnum=0;curfragnum<pattrib->nr_frags;curfragnum++){
				payload=(u8 *)RND4((SIZE_PTR)(payload));
				RT_TRACE(_module_rtl871x_xmit_c_,_drv_err_,("===curfragnum=%d, pframe= 0x%.2x, 0x%.2x, 0x%.2x, 0x%.2x, 0x%.2x, 0x%.2x, 0x%.2x, 0x%.2x,!!!\n",
					curfragnum,*payload, *(payload+1),*(payload+2),*(payload+3),*(payload+4),*(payload+5),*(payload+6),*(payload+7)));

				payload=payload+pattrib->hdrlen+pattrib->iv_len;
				RT_TRACE(_module_rtl871x_xmit_c_,_drv_err_,("curfragnum=%d pattrib->hdrlen=%d pattrib->iv_len=%d",curfragnum,pattrib->hdrlen,pattrib->iv_len));
				if((curfragnum+1)==pattrib->nr_frags){
					length=pattrib->last_txcmdsz-pattrib->hdrlen-pattrib->iv_len-( (pattrib->bswenc) ? pattrib->icv_len : 0);
					rtw_secmicappend(&micdata, payload,length);
					payload=payload+length;
				}
				else{
					length=pxmitpriv->frag_len-pattrib->hdrlen-pattrib->iv_len-( (pattrib->bswenc) ? pattrib->icv_len : 0);
					rtw_secmicappend(&micdata, payload, length);
					payload=payload+length+pattrib->icv_len;
					RT_TRACE(_module_rtl871x_xmit_c_,_drv_err_,("curfragnum=%d length=%d pattrib->icv_len=%d",curfragnum,length,pattrib->icv_len));
				}
			}
			rtw_secgetmic(&micdata,&(mic[0]));
			RT_TRACE(_module_rtl871x_xmit_c_,_drv_err_,("xmitframe_addmic: before add mic code!!!\n"));
			RT_TRACE(_module_rtl871x_xmit_c_,_drv_err_,("xmitframe_addmic: pattrib->last_txcmdsz=%d!!!\n",pattrib->last_txcmdsz));
			RT_TRACE(_module_rtl871x_xmit_c_,_drv_err_,("xmitframe_addmic: mic[0]=0x%.2x ,mic[1]=0x%.2x ,mic[2]=0x%.2x ,mic[3]=0x%.2x \n\
  mic[4]=0x%.2x ,mic[5]=0x%.2x ,mic[6]=0x%.2x ,mic[7]=0x%.2x !!!!\n",
				mic[0],mic[1],mic[2],mic[3],mic[4],mic[5],mic[6],mic[7]));
			//add mic code  and add the mic code length in last_txcmdsz

			_rtw_memcpy(payload, &(mic[0]),8);
			pattrib->last_txcmdsz+=8;
			
			RT_TRACE(_module_rtl871x_xmit_c_,_drv_info_,("\n ========last pkt========\n"));
			payload=payload-pattrib->last_txcmdsz+8;
			for(curfragnum=0;curfragnum<pattrib->last_txcmdsz;curfragnum=curfragnum+8)
					RT_TRACE(_module_rtl871x_xmit_c_,_drv_info_,(" %.2x,  %.2x,  %.2x,  %.2x,  %.2x,  %.2x,  %.2x,  %.2x ",
					*(payload+curfragnum), *(payload+curfragnum+1), *(payload+curfragnum+2),*(payload+curfragnum+3),
					*(payload+curfragnum+4),*(payload+curfragnum+5),*(payload+curfragnum+6),*(payload+curfragnum+7)));
			}
/*
			else{
				RT_TRACE(_module_rtl871x_xmit_c_,_drv_err_,("xmitframe_addmic: rtw_get_stainfo==NULL!!!\n"));
			}
*/		
	}
	
_func_exit_;

	return _SUCCESS;
}

static s32 xmitframe_swencrypt(_adapter *padapter, struct xmit_frame *pxmitframe){

	struct	pkt_attrib	 *pattrib = &pxmitframe->attrib;
	//struct 	security_priv	*psecuritypriv=&padapter->securitypriv;
	
_func_enter_;

	//if((psecuritypriv->sw_encrypt)||(pattrib->bswenc))	
	if(pattrib->bswenc)
	{
		//DBG_871X("start xmitframe_swencrypt\n");
		RT_TRACE(_module_rtl871x_xmit_c_,_drv_alert_,("### xmitframe_swencrypt\n"));
		switch(pattrib->encrypt){
		case _WEP40_:
		case _WEP104_:
			rtw_wep_encrypt(padapter, (u8 *)pxmitframe);
			break;
		case _TKIP_:
			rtw_tkip_encrypt(padapter, (u8 *)pxmitframe);
			break;
		case _AES_:
			rtw_aes_encrypt(padapter, (u8 * )pxmitframe);
			break;
#ifdef CONFIG_WAPI_SUPPORT
		case _SMS4_:
			rtw_sms4_encrypt(padapter, (u8 * )pxmitframe);
#endif
		default:
				break;
		}

	} else {
		RT_TRACE(_module_rtl871x_xmit_c_,_drv_notice_,("### xmitframe_hwencrypt\n"));
	}

_func_exit_;

	return _SUCCESS;
}

s32 rtw_make_wlanhdr (_adapter *padapter , u8 *hdr, struct pkt_attrib *pattrib)
{
	u16 *qc;

	struct rtw_ieee80211_hdr *pwlanhdr = (struct rtw_ieee80211_hdr *)hdr;
	struct mlme_priv *pmlmepriv = &padapter->mlmepriv;
	struct qos_priv *pqospriv = &pmlmepriv->qospriv;
	u8 qos_option = _FALSE;
#ifdef CONFIG_TDLS
	struct tdls_info *ptdlsinfo = &padapter->tdlsinfo;
	struct sta_priv 	*pstapriv = &padapter->stapriv;
	struct sta_info *ptdls_sta=NULL, *psta_backup=NULL;
	u8 direct_link=0;
#endif //CONFIG_TDLS

	sint res = _SUCCESS;
	u16 *fctrl = &pwlanhdr->frame_ctl;

	//struct sta_info *psta;

	//sint bmcst = IS_MCAST(pattrib->ra);

_func_enter_;

/*
	psta = rtw_get_stainfo(&padapter->stapriv, pattrib->ra);
	if(pattrib->psta != psta)
	{
		DBG_871X("%s, pattrib->psta(%p) != psta(%p)\n", __func__, pattrib->psta, psta);
		return;
	}

	if(psta==NULL)
	{
		DBG_871X("%s, psta==NUL\n", __func__);
		return _FAIL;
	}

	if(!(psta->state &_FW_LINKED))
	{
		DBG_871X("%s, psta->state(0x%x) != _FW_LINKED\n", __func__, psta->state);
		return _FAIL;
	}
*/

	_rtw_memset(hdr, 0, WLANHDR_OFFSET);

	SetFrameSubType(fctrl, pattrib->subtype);

	if (pattrib->subtype & WIFI_DATA_TYPE)
	{
		if ((check_fwstate(pmlmepriv,  WIFI_STATION_STATE) == _TRUE)) {
			//to_ds = 1, fr_ds = 0;
#ifdef CONFIG_TDLS
			if((ptdlsinfo->setup_state == TDLS_LINKED_STATE)){
				ptdls_sta = rtw_get_stainfo(pstapriv, pattrib->dst);
				if((ptdls_sta!=NULL)&&(ptdls_sta->tdls_sta_state & TDLS_LINKED_STATE)&&(pattrib->ether_type!=0x0806)){
					//TDLS data transfer, ToDS=0, FrDs=0
					_rtw_memcpy(pwlanhdr->addr1, pattrib->dst, ETH_ALEN);
					_rtw_memcpy(pwlanhdr->addr2, pattrib->src, ETH_ALEN);
					_rtw_memcpy(pwlanhdr->addr3, get_bssid(pmlmepriv), ETH_ALEN);
					direct_link=1;
				}else{
					// 1.Data transfer to AP
					// 2.Arp pkt will relayed by AP
					SetToDs(fctrl);							
					_rtw_memcpy(pwlanhdr->addr1, get_bssid(pmlmepriv), ETH_ALEN);
					_rtw_memcpy(pwlanhdr->addr2, pattrib->src, ETH_ALEN);
					_rtw_memcpy(pwlanhdr->addr3, pattrib->dst, ETH_ALEN);
				} 
			}else
#endif //CONFIG_TDLS
			{
				//Data transfer to AP
				SetToDs(fctrl);							
				_rtw_memcpy(pwlanhdr->addr1, get_bssid(pmlmepriv), ETH_ALEN);
				_rtw_memcpy(pwlanhdr->addr2, pattrib->src, ETH_ALEN);
				_rtw_memcpy(pwlanhdr->addr3, pattrib->dst, ETH_ALEN);
			} 

			if (pqospriv->qos_option)
				qos_option = _TRUE;

		}
		else if ((check_fwstate(pmlmepriv,  WIFI_AP_STATE) == _TRUE) ) {
			//to_ds = 0, fr_ds = 1;
			SetFrDs(fctrl);
			_rtw_memcpy(pwlanhdr->addr1, pattrib->dst, ETH_ALEN);
			_rtw_memcpy(pwlanhdr->addr2, get_bssid(pmlmepriv), ETH_ALEN);
			_rtw_memcpy(pwlanhdr->addr3, pattrib->src, ETH_ALEN);

			if(pattrib->qos_en)
				qos_option = _TRUE;
		}
		else if ((check_fwstate(pmlmepriv, WIFI_ADHOC_STATE) == _TRUE) ||
		(check_fwstate(pmlmepriv, WIFI_ADHOC_MASTER_STATE) == _TRUE)) {
			_rtw_memcpy(pwlanhdr->addr1, pattrib->dst, ETH_ALEN);
			_rtw_memcpy(pwlanhdr->addr2, pattrib->src, ETH_ALEN);
			_rtw_memcpy(pwlanhdr->addr3, get_bssid(pmlmepriv), ETH_ALEN);

			if(pattrib->qos_en)
				qos_option = _TRUE;
		}
		else {
			RT_TRACE(_module_rtl871x_xmit_c_,_drv_err_,("fw_state:%x is not allowed to xmit frame\n", get_fwstate(pmlmepriv)));
			res = _FAIL;
			goto exit;
		}

		if(pattrib->mdata)
			SetMData(fctrl);

		if (pattrib->encrypt)
			SetPrivacy(fctrl);

		if (qos_option)
		{
			qc = (unsigned short *)(hdr + pattrib->hdrlen - 2);

			if (pattrib->priority)
				SetPriority(qc, pattrib->priority);

			SetEOSP(qc, pattrib->eosp);

			SetAckpolicy(qc, pattrib->ack_policy);
		}

		//TODO: fill HT Control Field

		//Update Seq Num will be handled by f/w
		{
			struct sta_info *psta;
			psta = rtw_get_stainfo(&padapter->stapriv, pattrib->ra);
			if(pattrib->psta != psta)
			{
				DBG_871X("%s, pattrib->psta(%p) != psta(%p)\n", __func__, pattrib->psta, psta);
				return _FAIL;
			}

			if(psta==NULL)
			{
				DBG_871X("%s, psta==NUL\n", __func__);
				return _FAIL;
			}

			if(!(psta->state &_FW_LINKED))
			{
				DBG_871X("%s, psta->state(0x%x) != _FW_LINKED\n", __func__, psta->state);
				return _FAIL;
			}
		
			//if(psta)
			{
#ifdef CONFIG_TDLS
				if(direct_link==1)
				{
					psta_backup = psta;
					psta = ptdls_sta;
				}
#endif //CONFIG_TDLS

				psta->sta_xmitpriv.txseq_tid[pattrib->priority]++;
				psta->sta_xmitpriv.txseq_tid[pattrib->priority] &= 0xFFF;

				pattrib->seqnum = psta->sta_xmitpriv.txseq_tid[pattrib->priority];

				SetSeqNum(hdr, pattrib->seqnum);

#ifdef CONFIG_80211N_HT
				//check if enable ampdu
				if(pattrib->ht_en && psta->htpriv.ampdu_enable)
				{
					if(psta->htpriv.agg_enable_bitmap & BIT(pattrib->priority))
					pattrib->ampdu_en = _TRUE;
				}

				//re-check if enable ampdu by BA_starting_seqctrl
				if(pattrib->ampdu_en == _TRUE)
				{					
					u16 tx_seq;

					tx_seq = psta->BA_starting_seqctrl[pattrib->priority & 0x0f];
		
					//check BA_starting_seqctrl
					if(SN_LESS(pattrib->seqnum, tx_seq))
					{
						//DBG_871X("tx ampdu seqnum(%d) < tx_seq(%d)\n", pattrib->seqnum, tx_seq);
						pattrib->ampdu_en = _FALSE;//AGG BK
					}
					else if(SN_EQUAL(pattrib->seqnum, tx_seq))
					{					
						psta->BA_starting_seqctrl[pattrib->priority & 0x0f] = (tx_seq+1)&0xfff;
					
						pattrib->ampdu_en = _TRUE;//AGG EN
					}
					else
					{
						//DBG_871X("tx ampdu over run\n");
						psta->BA_starting_seqctrl[pattrib->priority & 0x0f] = (pattrib->seqnum+1)&0xfff;
						pattrib->ampdu_en = _TRUE;//AGG EN
					}

				}
#endif //CONFIG_80211N_HT
#ifdef CONFIG_TDLS
				if(direct_link==1)
				{
					if (pattrib->encrypt){
						pattrib->encrypt= _AES_;
						pattrib->iv_len=8;
						pattrib->icv_len=8;
					}

					//qos_en, ht_en, init rate, ,bw, ch_offset, sgi
					//pattrib->qos_en = ptdls_sta->qos_option;
					
					pattrib->raid = ptdls_sta->raid;
#ifdef CONFIG_80211N_HT
					pattrib->bwmode = ptdls_sta->htpriv.bwmode;
					pattrib->ht_en = ptdls_sta->htpriv.ht_option;
					pattrib->ch_offset = ptdls_sta->htpriv.ch_offset;
					pattrib->sgi= ptdls_sta->htpriv.sgi;
#endif //CONFIG_80211N_HT
					pattrib->mac_id = ptdls_sta->mac_id;

					psta = psta_backup;
				}
#endif //CONFIG_TDLS

			}
		}
		
	}
	else
	{

	}

exit:

_func_exit_;

	return res;
}

s32 rtw_txframes_pending(_adapter *padapter)
{
	struct xmit_priv *pxmitpriv = &padapter->xmitpriv;

	return ((_rtw_queue_empty(&pxmitpriv->be_pending) == _FALSE) || 
			 (_rtw_queue_empty(&pxmitpriv->bk_pending) == _FALSE) || 
			 (_rtw_queue_empty(&pxmitpriv->vi_pending) == _FALSE) ||
			 (_rtw_queue_empty(&pxmitpriv->vo_pending) == _FALSE));
}

s32 rtw_txframes_sta_ac_pending(_adapter *padapter, struct pkt_attrib *pattrib)
{	
	struct sta_info *psta;
	struct tx_servq *ptxservq;
	int priority = pattrib->priority;
/*
	if(pattrib->psta)
	{
		psta = pattrib->psta;
	}
	else
	{
		DBG_871X("%s, call rtw_get_stainfo()\n", __func__);
		psta=rtw_get_stainfo(&padapter->stapriv ,&pattrib->ra[0]);
	}	
*/
	psta = rtw_get_stainfo(&padapter->stapriv, pattrib->ra);
	if(pattrib->psta != psta)
	{
		DBG_871X("%s, pattrib->psta(%p) != psta(%p)\n", __func__, pattrib->psta, psta);
		return 0;
	}

	if(psta==NULL)
	{
		DBG_871X("%s, psta==NUL\n", __func__);
		return 0;
	}

	if(!(psta->state &_FW_LINKED))
	{
		DBG_871X("%s, psta->state(0x%x) != _FW_LINKED\n", __func__, psta->state);
		return 0;
	}
	
	switch(priority) 
	{
			case 1:
			case 2:
				ptxservq = &(psta->sta_xmitpriv.bk_q);				
				break;
			case 4:
			case 5:
				ptxservq = &(psta->sta_xmitpriv.vi_q);				
				break;
			case 6:
			case 7:
				ptxservq = &(psta->sta_xmitpriv.vo_q);							
				break;
			case 0:
			case 3:
			default:
				ptxservq = &(psta->sta_xmitpriv.be_q);							
			break;
	
	}	

	return ptxservq->qcnt;	
}

#ifdef CONFIG_TDLS

int rtw_build_tdls_ies(_adapter * padapter, struct xmit_frame * pxmitframe, u8 *pframe, u8 action)
{
	int res=_SUCCESS;

	switch(action){
		case TDLS_SETUP_REQUEST:
			rtw_build_tdls_setup_req_ies(padapter, pxmitframe, pframe);
			break;
		case TDLS_SETUP_RESPONSE:
			rtw_build_tdls_setup_rsp_ies(padapter, pxmitframe, pframe);
			break;
		case TDLS_SETUP_CONFIRM:
			rtw_build_tdls_setup_cfm_ies(padapter, pxmitframe, pframe);
			break;
		case TDLS_TEARDOWN:
			rtw_build_tdls_teardown_ies(padapter, pxmitframe, pframe);
			break;
		case TDLS_DISCOVERY_REQUEST:
			rtw_build_tdls_dis_req_ies(padapter, pxmitframe, pframe);
			break;			
		case TDLS_PEER_TRAFFIC_INDICATION:
			rtw_build_tdls_peer_traffic_indication_ies(padapter, pxmitframe, pframe);
			break;
		case TDLS_CHANNEL_SWITCH_REQUEST:
			rtw_build_tdls_ch_switch_req_ies(padapter, pxmitframe, pframe);
			break;
		case TDLS_CHANNEL_SWITCH_RESPONSE:
			rtw_build_tdls_ch_switch_rsp_ies(padapter, pxmitframe, pframe);
			break;
#ifdef CONFIG_WFD			
		case TUNNELED_PROBE_REQ:
			rtw_build_tunneled_probe_req_ies(padapter, pxmitframe, pframe);
			break;
		case TUNNELED_PROBE_RSP:
			rtw_build_tunneled_probe_rsp_ies(padapter, pxmitframe, pframe);
			break;
#endif //CONFIG_WFD
		default:
			res=_FAIL;
			break;
	}

	return res;
}

s32 rtw_make_tdls_wlanhdr (_adapter *padapter , u8 *hdr, struct pkt_attrib *pattrib, u8 action)
{
	u16 *qc;
	struct rtw_ieee80211_hdr *pwlanhdr = (struct rtw_ieee80211_hdr *)hdr;
	struct mlme_priv *pmlmepriv = &padapter->mlmepriv;
	struct qos_priv *pqospriv = &pmlmepriv->qospriv;
	struct sta_priv 	*pstapriv = &padapter->stapriv;
	struct sta_info *psta=NULL, *ptdls_sta=NULL;
	u8 tdls_seq=0, baddr[ETH_ALEN] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

	sint res = _SUCCESS;
	u16 *fctrl = &pwlanhdr->frame_ctl;

_func_enter_;

	_rtw_memset(hdr, 0, WLANHDR_OFFSET);

	SetFrameSubType(fctrl, pattrib->subtype);

	switch(action){
		case TDLS_SETUP_REQUEST:
		case TDLS_SETUP_RESPONSE:
		case TDLS_SETUP_CONFIRM:
		case TDLS_TEARDOWN:	//directly to peer STA or via AP
		case TDLS_PEER_TRAFFIC_INDICATION:
		case TDLS_PEER_PSM_REQUEST:	//directly to peer STA or via AP
		case TUNNELED_PROBE_REQ:
		case TUNNELED_PROBE_RSP:
			SetToDs(fctrl);							
			_rtw_memcpy(pwlanhdr->addr1, get_bssid(pmlmepriv), ETH_ALEN);
			_rtw_memcpy(pwlanhdr->addr2, pattrib->src, ETH_ALEN);
			_rtw_memcpy(pwlanhdr->addr3, pattrib->dst, ETH_ALEN);
			break;
		case TDLS_CHANNEL_SWITCH_REQUEST:
		case TDLS_CHANNEL_SWITCH_RESPONSE:
		case TDLS_PEER_PSM_RESPONSE:
		case TDLS_PEER_TRAFFIC_RESPONSE:
			_rtw_memcpy(pwlanhdr->addr1, pattrib->dst, ETH_ALEN);
			_rtw_memcpy(pwlanhdr->addr2, pattrib->src, ETH_ALEN);
			_rtw_memcpy(pwlanhdr->addr3, get_bssid(pmlmepriv), ETH_ALEN);
			tdls_seq=1;
			break;
		case TDLS_DISCOVERY_REQUEST:	//unicast: directly to peer sta, Bcast: via AP
			if(_rtw_memcmp(pattrib->dst, baddr, ETH_ALEN) )
			{
				SetToDs(fctrl);							
				_rtw_memcpy(pwlanhdr->addr1, get_bssid(pmlmepriv), ETH_ALEN);
				_rtw_memcpy(pwlanhdr->addr2, pattrib->src, ETH_ALEN);
				_rtw_memcpy(pwlanhdr->addr3, pattrib->dst, ETH_ALEN);
			}
			else
			{
				_rtw_memcpy(pwlanhdr->addr1, pattrib->dst, ETH_ALEN);
				_rtw_memcpy(pwlanhdr->addr2, pattrib->src, ETH_ALEN);
				_rtw_memcpy(pwlanhdr->addr3, get_bssid(pmlmepriv), ETH_ALEN);
				tdls_seq=1;
			}
			break;
	}

	if (pattrib->encrypt)
		SetPrivacy(fctrl);

	if (pqospriv->qos_option)
	{
		qc = (unsigned short *)(hdr + pattrib->hdrlen - 2);
		if (pattrib->priority)
			SetPriority(qc, pattrib->priority);
		SetAckpolicy(qc, pattrib->ack_policy);
	}

	psta = pattrib->psta;
 
	//  1. update seq_num per link by sta_info
	//  2. rewrite encrypt to _AES_, also rewrite iv_len, icv_len
	if(tdls_seq==1){
		ptdls_sta=rtw_get_stainfo(pstapriv, pattrib->dst);
		if(ptdls_sta){
			ptdls_sta->sta_xmitpriv.txseq_tid[pattrib->priority]++;
			ptdls_sta->sta_xmitpriv.txseq_tid[pattrib->priority] &= 0xFFF;
			pattrib->seqnum = ptdls_sta->sta_xmitpriv.txseq_tid[pattrib->priority];
			SetSeqNum(hdr, pattrib->seqnum);

			if (pattrib->encrypt){
				pattrib->encrypt= _AES_;
				pattrib->iv_len=8;
				pattrib->icv_len=8;
			}
		}else{
			res=_FAIL;
			goto exit;
		}
	}else if(psta){
		psta->sta_xmitpriv.txseq_tid[pattrib->priority]++;
		psta->sta_xmitpriv.txseq_tid[pattrib->priority] &= 0xFFF;
		pattrib->seqnum = psta->sta_xmitpriv.txseq_tid[pattrib->priority];
		SetSeqNum(hdr, pattrib->seqnum);
	}


exit:

_func_exit_;

	return res;
}

s32 rtw_xmit_tdls_coalesce(_adapter * padapter, struct xmit_frame * pxmitframe, u8 action)
{
	s32 llc_sz;

	u8 *pframe, *mem_start;

	struct sta_info		*psta;
	struct sta_priv		*pstapriv = &padapter->stapriv;
	struct mlme_priv	*pmlmepriv = &padapter->mlmepriv;
	struct pkt_attrib	*pattrib = &pxmitframe->attrib;
	u8 *pbuf_start;
	s32 bmcst = IS_MCAST(pattrib->ra);
	s32 res = _SUCCESS;
	
_func_enter_;

	if (pattrib->psta) {
		psta = pattrib->psta;
	} else {	
		if(bmcst) {
			psta = rtw_get_bcmc_stainfo(padapter);
		} else {
			psta = rtw_get_stainfo(&padapter->stapriv, pattrib->ra);
	        }
	}

	if(psta==NULL)
		return _FAIL;

	if (pxmitframe->buf_addr == NULL)
		return _FAIL;

	pbuf_start = pxmitframe->buf_addr;
	mem_start = pbuf_start + TXDESC_OFFSET;

	if (rtw_make_tdls_wlanhdr(padapter, mem_start, pattrib, action) == _FAIL) {
		res = _FAIL;
		goto exit;
	}

	pframe = mem_start;
	pframe += pattrib->hdrlen;

	//adding icv, if necessary...
	if (pattrib->iv_len)
	{
		if (psta != NULL)
		{
			switch(pattrib->encrypt)
			{
				case _WEP40_:
				case _WEP104_:
						WEP_IV(pattrib->iv, psta->dot11txpn, pattrib->key_idx);	
					break;
				case _TKIP_:			
					if(bmcst)
						TKIP_IV(pattrib->iv, psta->dot11txpn, pattrib->key_idx);
					else
						TKIP_IV(pattrib->iv, psta->dot11txpn, 0);
					break;			
				case _AES_:
					if(bmcst)
						AES_IV(pattrib->iv, psta->dot11txpn, pattrib->key_idx);
					else
						AES_IV(pattrib->iv, psta->dot11txpn, 0);
					break;
			}
		}

		_rtw_memcpy(pframe, pattrib->iv, pattrib->iv_len);
		pframe += pattrib->iv_len;

	}

	llc_sz = rtw_put_snap(pframe, pattrib->ether_type);
	pframe += llc_sz;

	//pattrib->pktlen will be counted in rtw_build_tdls_ies
	pattrib->pktlen = 0;

	rtw_build_tdls_ies(padapter, pxmitframe, pframe, action);

	if ((pattrib->icv_len >0 )&& (pattrib->bswenc)) {
		pframe += pattrib->pktlen;
		_rtw_memcpy(pframe, pattrib->icv, pattrib->icv_len); 
		pframe += pattrib->icv_len;
	}

	pattrib->nr_frags = 1;
	pattrib->last_txcmdsz = pattrib->hdrlen + pattrib->iv_len + llc_sz + 
			((pattrib->bswenc) ? pattrib->icv_len : 0) + pattrib->pktlen;
	
	if (xmitframe_addmic(padapter, pxmitframe) == _FAIL)
	{
		goto exit;
	}

	xmitframe_swencrypt(padapter, pxmitframe);
	
	update_attrib_vcs_info(padapter, pxmitframe);
	
exit:	
	
_func_exit_;	

	return res;
}
#endif //CONFIG_TDLS

/*
 * Calculate wlan 802.11 packet MAX size from pkt_attrib
 * This function doesn't consider fragment case
 */
u32 rtw_calculate_wlan_pkt_size_by_attribue(struct pkt_attrib *pattrib)
{
	u32	len = 0;

	len = pattrib->hdrlen + pattrib->iv_len; // WLAN Header and IV
	len += SNAP_SIZE + sizeof(u16); // LLC
	len += pattrib->pktlen;
	if (pattrib->encrypt == _TKIP_) len += 8; // MIC
	len += ((pattrib->bswenc) ? pattrib->icv_len : 0); // ICV

	return len;
}

/*

This sub-routine will perform all the following:

1. remove 802.3 header.
2. create wlan_header, based on the info in pxmitframe
3. append sta's iv/ext-iv
4. append LLC
5. move frag chunk from pframe to pxmitframe->mem
6. apply sw-encrypt, if necessary. 

*/
s32 rtw_xmitframe_coalesce(_adapter *padapter, _pkt *pkt, struct xmit_frame *pxmitframe)
{
	struct pkt_file pktfile;

	s32 frg_inx, frg_len, mpdu_len, llc_sz, mem_sz;

	SIZE_PTR addr;

	u8 *pframe, *mem_start;
	u8 hw_hdr_offset;

	//struct sta_info		*psta;
	//struct sta_priv		*pstapriv = &padapter->stapriv;
	//struct mlme_priv	*pmlmepriv = &padapter->mlmepriv;
	struct xmit_priv	*pxmitpriv = &padapter->xmitpriv;

	struct pkt_attrib	*pattrib = &pxmitframe->attrib;

	u8 *pbuf_start;

	s32 bmcst = IS_MCAST(pattrib->ra);
	s32 res = _SUCCESS;

_func_enter_;

/*
	if (pattrib->psta)
	{
		psta = pattrib->psta;
	} else
	{	
		DBG_871X("%s, call rtw_get_stainfo()\n", __func__);
		psta = rtw_get_stainfo(&padapter->stapriv, pattrib->ra);
	}

	if(psta==NULL)
        {
		
		DBG_871X("%s, psta==NUL\n", __func__);
		return _FAIL;
	}


	if(!(psta->state &_FW_LINKED))
	{
		DBG_871X("%s, psta->state(0x%x) != _FW_LINKED\n", __func__, psta->state);
		return _FAIL;
	}
*/
	if (pxmitframe->buf_addr == NULL){
		DBG_8192C("==> %s buf_addr==NULL \n",__FUNCTION__);
		return _FAIL;
	}

	pbuf_start = pxmitframe->buf_addr;
	
#ifdef CONFIG_USB_TX_AGGREGATION
	hw_hdr_offset =  TXDESC_SIZE + (pxmitframe->pkt_offset * PACKET_OFFSET_SZ);
#else
	#ifdef CONFIG_TX_EARLY_MODE //for SDIO && Tx Agg
	hw_hdr_offset = TXDESC_OFFSET + EARLY_MODE_INFO_SIZE;
	#else
	hw_hdr_offset = TXDESC_OFFSET;
	#endif
#endif

	mem_start = pbuf_start +	hw_hdr_offset;

	if (rtw_make_wlanhdr(padapter, mem_start, pattrib) == _FAIL) {
		RT_TRACE(_module_rtl871x_xmit_c_, _drv_err_, ("rtw_xmitframe_coalesce: rtw_make_wlanhdr fail; drop pkt\n"));
		DBG_8192C("rtw_xmitframe_coalesce: rtw_make_wlanhdr fail; drop pkt\n");
		res = _FAIL;
		goto exit;
	}

	_rtw_open_pktfile(pkt, &pktfile);
	_rtw_pktfile_read(&pktfile, NULL, pattrib->pkt_hdrlen);

	frg_inx = 0;
	frg_len = pxmitpriv->frag_len - 4;//2346-4 = 2342

	while (1)
	{
		llc_sz = 0;

		mpdu_len = frg_len;

		pframe = mem_start;

		SetMFrag(mem_start);

		pframe += pattrib->hdrlen;
		mpdu_len -= pattrib->hdrlen;

		//adding icv, if necessary...
		if (pattrib->iv_len)
		{
/*		
			//if (check_fwstate(pmlmepriv, WIFI_MP_STATE))
			//	psta = rtw_get_stainfo(pstapriv, get_bssid(pmlmepriv));
			//else
			//	psta = rtw_get_stainfo(pstapriv, pattrib->ra);

			if (psta != NULL)
			{
				switch(pattrib->encrypt)
				{
					case _WEP40_:
					case _WEP104_:
							WEP_IV(pattrib->iv, psta->dot11txpn, pattrib->key_idx);	
						break;
					case _TKIP_:			
						if(bmcst)
							TKIP_IV(pattrib->iv, psta->dot11txpn, pattrib->key_idx);
						else
							TKIP_IV(pattrib->iv, psta->dot11txpn, 0);
						break;			
					case _AES_:
						if(bmcst)
							AES_IV(pattrib->iv, psta->dot11txpn, pattrib->key_idx);
						else
							AES_IV(pattrib->iv, psta->dot11txpn, 0);
						break;
#ifdef CONFIG_WAPI_SUPPORT
					case _SMS4_:
						rtw_wapi_get_iv(padapter,pattrib->ra,pattrib->iv);
						break;
#endif
				}
			}
*/
			_rtw_memcpy(pframe, pattrib->iv, pattrib->iv_len);

			RT_TRACE(_module_rtl871x_xmit_c_, _drv_notice_,
				 ("rtw_xmitframe_coalesce: keyid=%d pattrib->iv[3]=%.2x pframe=%.2x %.2x %.2x %.2x\n",
				  padapter->securitypriv.dot11PrivacyKeyIndex, pattrib->iv[3], *pframe, *(pframe+1), *(pframe+2), *(pframe+3)));

			pframe += pattrib->iv_len;

			mpdu_len -= pattrib->iv_len;
		}

		if (frg_inx == 0) {
			llc_sz = rtw_put_snap(pframe, pattrib->ether_type);
			pframe += llc_sz;
			mpdu_len -= llc_sz;
		}

		if ((pattrib->icv_len >0) && (pattrib->bswenc)) {
			mpdu_len -= pattrib->icv_len;
		}


		if (bmcst) {
			// don't do fragment to broadcat/multicast packets
			mem_sz = _rtw_pktfile_read(&pktfile, pframe, pattrib->pktlen);
		} else {
			mem_sz = _rtw_pktfile_read(&pktfile, pframe, mpdu_len);
		}

		pframe += mem_sz;

		if ((pattrib->icv_len >0 )&& (pattrib->bswenc)) {
			_rtw_memcpy(pframe, pattrib->icv, pattrib->icv_len); 
			pframe += pattrib->icv_len;
		}

		frg_inx++;

		if (bmcst || (rtw_endofpktfile(&pktfile) == _TRUE))
		{
			pattrib->nr_frags = frg_inx;

			pattrib->last_txcmdsz = pattrib->hdrlen + pattrib->iv_len + ((pattrib->nr_frags==1)? llc_sz:0) + 
					((pattrib->bswenc) ? pattrib->icv_len : 0) + mem_sz;
			
			ClearMFrag(mem_start);

			break;
		} else {
			RT_TRACE(_module_rtl871x_xmit_c_, _drv_err_, ("%s: There're still something in packet!\n", __FUNCTION__));
		}

		addr = (SIZE_PTR)(pframe);

		mem_start = (unsigned char *)RND4(addr) + hw_hdr_offset;
		_rtw_me:% Img/no¼"˜İ& uÍ—™visio^;licş`!øbå+ lF/ fr/]¬6¸ B\ 2o%:, oixz‚/ui0	 s©+iéla("R'B& aØèqÔ~2 Xş  .mondocte[Fº#lbüWÆÁ5.£dh¥nhemï%bsf-bg9œ6 reloaÍ gMŠ+vor	ø­[µğ lh d¡Xı<å¯á+on?1en2× eC1ú	­F- l¾(lycb wbanM“eduplì,teÁCNC e¤%°AærDMXogp%V@	 l°2 l:so›7´© ˆ¢“Iµª= zelip7neâzD>r;baÓleplan'"f.ãespmaghrİ² /58JibäM t'A.jsU;MpienFª pm>s-d>%jş»²À-²ikebag±%6( . M4il±† *"¹adíI wt nÓ) l| pj>!18an	 ^B˜careö:æpole-mú±²iveŠÁ` *ã2‰iv\ o-)Z -Fálocal-1oi	¡Î
% -IQ¼ aN*?%’. -ç>s-bYjYeu/-†ogic-… be/eú9/new¯f:AY&/áommf!‹JQÇ;t. ´± woá>lp.amt*0y	3prsV, *0s-!á
Bğ	lr>ÑêNmacsid’'å& dugrizzly1Ïmadâ’ i1èRWmagik@5!©ÇFç%maig&{	àmaEq- y.voir-M% -/au"©6"h mù;e-foŠjyE*.CW<riğ¯’?+"¸@…xannuGmax"„\ oNÍI¸ /1`iph_wea MimumE2­¤topˆIpY!	!¾ub”Cyakad›½Frai²&©¤8 -fL–&½G	7U% .*û| gv! b"Z
2#	Ïš—œeDETdstaër *á¹Qs-dyn©±C6# OMí0¿œRE 	Ba`©gBeva˜‰.Á…¡ÕõœeB i.8!@` x%BFI-,Nw1120x600"¤  mı,ur-§»ı=Á@ƒõ'*Ø>-ç"#F"  lG3fÈê1ìmbersruà getŞphpBümerci¾	!™>Ğ-xìsalogub2. -j2†İK i–Y¡ğac¥È…U thode-finND{ ^mq> mey/#í…?q­³F, ia0	dmg2åI!+|>mini-{*jeuZ»mism-)*"x¹WMÅissdarjjAJãmoeXa"%Ÿ°;mon-"¾…ÕE)7on-ptYÍmonca"Ö?bÎî
 e*;ÄYs‹isez.xxx+3ntjeâ) fªF K3 lÁ;TÕx aí	QXPovijo)Ë9<R!A>-t­=got2lEmotto"ÑŸMiöBAiholdÍmovi~AmozooJQ1mvch">3Í+mwzi©õ!.%Pmydirtyhobby.de/?naffMÅ):! V k.‹my ©ÿ . LJ?Fßynew"1T eÔ­2Ìô¬>]myposK^*25îKswfJ+yxá^*&‹($nakedteensf-eo^Be  neko-hent¬,!5i4%neotokyÓ)P tN8«`¡wg/monitoİ6é7neÁ—Äa -Ş n6Ä*I tíwnetD7152Å+	šjuk	—oo/á;teolakm2E90alcr » gÕˆã; n¸pƒ2ë ousli¼RÑ
 ^Bü&•¬noviy³#'v.} uÄaúaZromD=nuit-tÀW½9-—yu-ny	 bg&øochÓ2BÄ åÔğ&ÇG>—#$
B& hles«z§.Ñ$ok5p85y1huc%ÒokpÏsÅ'åºBTon-veutj0cu­	=># xa¢Wnly!÷es.à/avata%l½	onvù9!Z	Ğf	
"tsin"k	¬pe	y0.co/cdn-cgi/p g2iÚ!^*.html."Fw[Ê;¸ran"w*/lang-p¾ -.H 	Œve£2-kiwØ^*L=7#P6( MQjs/OB.Dz¬ aŞ8„oxiza[wwÿ	Bxyä]/er/odLî yA*.	i@M{´Ü6 ackbBõ p¢:“}(parlonspisc)%Y]&“G p-ts€áÌÃ .*32 s.cmptchV: net · tDIR¿¶^s.pmu>s s.orhqzuvend..ÚB"¡à iÀDub)×J  1dv.j\Ä®6un>„	ƒet\‡garc)ŠR0	&eZ*/±G©^	Hhi[dİG…´ /X/cptÍ4u -!^%´"piazzaR -'M½!Y*l±š¼^šnet49x^*?/É	G^D"X#	Öla!ø-d*-reuŠ(V$,™#A• pTS	hA}*IÜBé pÍwaw5- yãª	–ointsì©^ŠN ok;kš.½7 p%aôi£iğ%ïsite_id.	QÌ2Ö@paid.orn¿A…ÄÓ aïur2I/…P!DJF*%toxicŞ s-rnıš=ZlA>yt"^°2“ gahyv¥Nur´%g1~urlesm*“j-wer¬NÂÛŒ cN\ p(sanIp^*_wAuctÅDMŸremium	UÓ2ŸriceC4p^*/ral_)/
FXJ8 ¹er_1ÑülegpÉer.roum |füpro@#Qb	¯&Er .ÚJ#)<Ş.caraES.  h4)¯ejacu|MK1	Kjapanhd*CReuÙpGQı sØ:%Fo !Ÿ i2mbr2Ápa‹Ğ…IFÒ$ o_`~ s>º'O.! é -­! Ë"r…'ëtha@DEÃ¡? lZ e–> s.celebriœŠ!€/?c6& Ô." -3qäl-eaual c§OÕœdu½ eÁsqøronoñAçfr/bookú.$rs/unibet/ú120_uAÖŸno-J8% fĞD¼rotect­RâA‘ tp-ÿcba	pcpm÷ub=A s!˜ yõA sáï	sub.airUq n|OÅõ-duJ o1ƒáó uGÆ a¬,K #e-ldl?ÅA o¨&x‰S"•µOF§ -–¥$, lEs-)*ÁÎ)ÕVÏure-wareÑc/butÕWÙĞ uøDÑ3!C:öif+ w©“quebec	J!‹r%¥yİquÑª-p u"	*/`i)­ ;0 l”ĞD:o  tPÂOic7‰ainfw¤ m2\	$Fw!¥‘ñNwrat|t aÑgF©indigCÕca/e$ krealnswa©:Ä rapgt%¯ "ô=EP{wsJÃ edC>r‚reef-guÏ# a@£NË Q"r.us/?*&b	[".*refgü3&­"•	 rŠn-ag’%ÿ¼ubsF+_u jetm-techEJü gÉ×VE oÑ=fr/?B% rtÃ-epÁ-hW nË/resha NWndez-vo»z&P CaÚtsI‘rhUDA>/*"Y.áU[ a…L-d… 	Œá ÑïV„ro)ll÷(n6 ¥7roxp€‚abà	é~³oyal"ÜA÷^]L*umeajeL-C±Ô^Õ(rue8d089m4 -	ñueÏÎ¯ ií<B3re5A@7+.#Ò les/*Yã2gby…×ûá‰b¶"˜$	bwab…2Y»s-sfrAd_ s/authMsgs.b"‡K^*/øU/co 	/$oÔ´_ sˆJ*',/e/qFAmuzNju		->_Q‘‘Éµ0¦V( fX1²á&-4	* a´PÁˆ-j=AÁ%Í cÚS o':)sous-N't.	Qearggü.¹ eo&/esy.esbV°.frC*?2”K s6ñ3tvJ& ã-µ\% a2®sex-is-áØ•–af-au-bo	E8B&‘Ü m¯¥ÅFe e-venF.!XR=K .nÂves-touVf+ a˜µm»øm¹K fÁûn 12çexe° bJ{"[
Î
Éi0A-cock"ôUÅ¬¡& oÇb¹ y.¥b-reche?·jOq.yakoÑTJL'r sğ!{AÜM„ xÄ…nui¸<8 e.’;s€2  >Î&‚oÉm‚¤ yñl&Ğ  s2~ ftPWáÿg/aP» ge(rep¬‰&*$û	ß</man^ğÏ pe‘ú4 oÎ#cat# /­edš7ş<HECİÎsheJe$(ş#B# short-stu_T	 p‘±_ t‚BS	@urN&piup0Å;	×imabioaâÈ _FÇ$_©L6te.elk'Çg né¯+QWJV xtyonÄaŞ ?ù_aign‘skrv)!G-…ky-b2%_c/P´*naria\skyG"be^*_?ƒerbù§
sle.pnjaune­½lic&FK¼™Ôl%madmoizi:!”	òm-AîJê 0ocial.yoox.it¶>é.F*boBàbé^P [ˆt"Ğ$	AcxN> ft-* /; ."soltanat×6qzatnawqÓ 	÷oonnig¸œv?width-¼Vt61±oè †HÀ"ÃËN± uss…6hpace-ñ©

!Ö-±ÒoQá/!P¡êÈ	Fx&:û +uhpar"97E3cm–ÍKMş£t .å(Òß	òpil&Ñ
šapiDne†"AsorIAèaE!4 -µÍtivƒ	( %htd
AGM>	sl-	¦“4â_AÄ±Fİ_ssl.g	ÏC ^Y…Bìy%ssŸ²JÊ[”öÙHU2Œmâ	$fotol«4 p{0 *Sİ¡	'mntz­)]	polÉ1!zi/VgnAûcQ	&"„
M#a/mire_o.L ¡§tim©ËOjs/u8NNGÍ”/mc0 _AU*/body2Z orefolÛ/?W m;"3"lmâ tµô r3>	"¦œ­ŞV@ Ó( ;il.Úİ2]Ò	J  s½<õ6<  e#’/ad·9½É¡m!Æ­”Il/*fV90JU u"`á>Ü uper-viraü?^$>òò--mG8a~furf-	áLáó cBK#	ëurf…. c¨)ËÍH u½. r_·!4"¤(t5hkmjkmhfae÷I›tac2.xcar eF%tadp
Nö AL x2taA 
"tcweb";ØÄ,ubi_ûj…í.a 4custom-php/tbr½5ä&s3? ; nD(saintjosephIaddon/®5/*?‰7 gFs3teen-.4ĞaáJeliad!]Q&É*‘°5¥Ymixé¾ixel-Á­" st-psychocr©±sortir‰p m7O¾ tinypÊAPEq~…LEco‡mig‡? |F9¸ŒA±EfE .“ks-v³sÂJ i¡6ÈigaÀvpsg lmajlp2*54 oV 24*	ƒBùÉP.reelvio /…;_pdZ_dp¸N: $tsurlesabd o""Ñî s"iFZ9å# .log!Fù	#mdsm›r$	ş• u¤*/*N6fÁ1y.\+elEOe
Å€ *H --c.emvĞvisor.&<0BrøÕ a' P' F¢)rPo3†)qJS  Wš¿ E‚--*&$nerI…$W’L	 ^B;)arÚ /*ôudo…tJ0 uti!–erƒ m I>ìtut;
 h&ËF#  vÎ.­zweng—#a—_F-ucoza88/cgi/uutils.fcg‰— uì%Ù*/aS]ugcæ]ient-a.2pk%S u1fr/*ê$uki©hit?Mô	0 lZW1[,AÆ j¨!%I> h.şã /-¿#Junif7*ş
…l:Ú	unißst¯‚/rÔcn_©*B†up-0O2up07^	Ì pÍ'waveÓ-5( /7"H.uptojiz%F?uraf„lub.2zph-E s-Fs-ugc-aø" a»j}=!R~ ss"Ú /¡ewaooh2Gõvcc.&b’â&ò"¿mvoiàÁ^.)B­verni\f!'1…#;/300x30JáviùÌ dë• i.K+ .Õ/.€Fı0 o%}mnc)/: vedrmÎ4plaza*/aab/pul¯¦éâsvm!YgiŒ.-? p>Ê|²3±O.CMF_Ë"37 -Ğa‡Mñx-PTä@2l teunÕ0!÷22E”viwiiş‰…N& o%Ê-ligi´RŸ#ou»#V :9 á
ÕT67 . 5hut"©,!WQ()c -[=wêß%&\M9QÈovni¡.«!#) pq*%ò!Å c‚s/‚.rÌ.E  1æF l6Ë)×¸F_vpn^»Ç6/ ñmoŠã nĞCF[ 0 -de i%¡|smart¼.?w3"ı	*$,wac.a164.tau2ëœ2 ¼	åÿvŸ2ˆwaÜ8:¾ ˜”ÕHwa‰Zû."Ó>pubhig+H	 ^*#A3LStart=1&forceOASTag=2›Ò tfs	ŞÚmyg¸.Œ	bz1Kk m>•< wîco.iluS	3eb-‡Ü!?.ºƒÉilon.e²
=™­Ã#ool6¥m2‹ ebT0erh¡2q|selÆ/WeEd8r/FormulaireDemÕ"pxéı÷>F´° i$J…aBú-ŸÃ i3$YebuÔ o©îjs/¸_badg"};weedÄŠfráå ccgåÌ eünFÅ wŒrnunVfr^*/H"²‡?srcrZ A&3K &i)ï	.ach:@wFß * h<barneb"¶Gs."x#ag&_‹>Ì		J v¦+ g4û$ oB- M *NÍ@*?resize=468%2C60	Œ2 722 922 d	 l#ôrn 300%2C38	ntpn.g
Ÿ	 V“x.aøaô.iDx19h¬=Fµxavbox36R	aiH	"EI£!s/*-87#D&?dscl2¦	A( &Äh]xlo9m. ø* e:!m‚‘4skip÷ t} |y434vng5¥71%2yaa"”‹>zye·ap¥œ/twnM yv5!_hl/ap"H*/HP_*ôyouÉFÇ$abdelghanihv"@|zevpeˆ	š@ *aô p2¬`esoxË ` |µ7_BUF_ALLOC);
		}
	}
	#ifdef DBG_XMIT_BUF
	else
	{
		DBG_871X("DBG_XMIT_BUF rtw_alloc_xmitbuf return NULL\n");
	}
	#endif

	_exit_critical(&pfree_xmitbuf_queue->lock, &irqL);

_func_exit_;

	return pxmitbuf;
}

s32 rtw_free_xmitbuf(struct xmit_priv *pxmitpriv, struct xmit_buf *pxmitbuf)
{
	_irqL irqL;
	_queue *pfree_xmitbuf_queue = &pxmitpriv->free_xmitbuf_queue;

_func_enter_;

	//DBG_871X("+rtw_free_xmitbuf\n");

	if(pxmitbuf==NULL)
	{
		return _FAIL;
	}

	if (pxmitbuf->sctx) {
		DBG_871X("%s pxmitbuf->sctx is not NULL\n", __func__);
		rtw_sctx_done_err(&pxmitbuf->sctx, RTW_SCTX_DONE_BUF_FREE);
	}

	if(pxmitbuf->buf_tag == XMITBUF_CMD) {
	}
	else if(pxmitbuf->buf_tag == XMITBUF_MGNT) {
		rtw_free_xmitbuf_ext(pxmitpriv, pxmitbuf);
	}
	else
	{
		_enter_critical(&pfree_xmitbuf_queue->lock, &irqL);

		rtw_list_delete(&pxmitbuf->list);	

		rtw_list_insert_tail(&(pxmitbuf->list), get_list_head(pfree_xmitbuf_queue));

		pxmitpriv->free_xmitbuf_cnt++;
		//DBG_871X("FREE, free_xmitbuf_cnt=%d\n", pxmitpriv->free_xmitbuf_cnt);
		#ifdef DBG_XMIT_BUF
		DBG_871X("DBG_XMIT_BUF FREE no=%d, free_xmitbuf_cnt=%d\n",pxmitbuf->no ,pxmitpriv->free_xmitbuf_cnt);
		#endif
		_exit_critical(&pfree_xmitbuf_queue->lock, &irqL);
	}

_func_exit_;	 

	return _SUCCESS;	
} 

void rtw_init_xmitframe(struct xmit_frame *pxframe)
{
	if (pxframe !=  NULL)//default value setting
	{
		pxframe->buf_addr = NULL;
		pxframe->pxmitbuf = NULL;

		_rtw_memset(&pxframe->attrib, 0, sizeof(struct pkt_attrib));
		//pxframe->attrib.psta = NULL;

		pxframe->frame_tag = DATA_FRAMETAG;

#ifdef CONFIG_USB_HCI
		pxframe->pkt = NULL;
		pxframe->pkt_offset = 1;//default use pkt_offset to fill tx desc

#ifdef CONFIG_USB_TX_AGGREGATION
		pxframe->agg_num = 1;
#endif

#endif //#ifdef CONFIG_USB_HCI

#if defined(CONFIG_SDIO_HCI) || defined(CONFIG_GSPI_HCI)
		pxframe->pg_num = 1;
		pxframe->agg_num = 1;
#endif

#ifdef CONFIG_XMIT_ACK
		pxframe->ack_report = 0;
#endif

	}
}

/*
Calling context:
1. OS_TXENTRY
2. RXENTRY (rx_thread or RX_ISR/RX_CallBack)

If we turn on USE_RXTHREAD, then, no need for critical section.
Otherwise, we must use _enter/_exit critical to protect free_xmit_queue...

Must be very very cautious...

*/
struct xmit_frame *rtw_alloc_xmitframe(struct xmit_priv *pxmitpriv)//(_queue *pfree_xmit_queue)
{
	/*
		Please remember to use all the osdep_service api,
		and lock/unlock or _enter/_exit critical to protect 
		pfree_xmit_queue
	*/

	_irqL irqL;
	struct xmit_frame *pxframe = NULL;
	_list *plist, *phead;
	_queue *pfree_xmit_queue = &pxmitpriv->free_xmit_queue;

_func_enter_;

	_enter_critical_bh(&pfree_xmit_queue->lock, &irqL);

	if (_rtw_queue_empty(pfree_xmit_queue) == _TRUE) {
		RT_TRACE(_module_rtl871x_xmit_c_,_drv_info_,("rtw_alloc_xmitframe:%d\n", pxmitpriv->free_xmitframe_cnt));
		pxframe =  NULL;
	} else {
		phead = get_list_head(pfree_xmit_queue);

		plist = get_next(phead);

		pxframe = LIST_CONTAINOR(plist, struct xmit_frame, list);

		rtw_list_delete(&(pxframe->list));
		pxmitpriv->free_xmitframe_cnt--;
		RT_TRACE(_module_rtl871x_xmit_c_, _drv_info_, ("rtw_alloc_xmitframe():free_xmitframe_cnt=%d\n", pxmitpriv->free_xmitframe_cnt));
	}

	_exit_critical_bh(&pfree_xmit_queue->lock, &irqL);

	rtw_init_xmitframe(pxframe);

_func_exit_;

	return pxframe;
}

struct xmit_frame *rtw_alloc_xmitframe_ext(struct xmit_priv *pxmitpriv)
{
	_irqL irqL;
	struct xmit_frame *pxframe = NULL;
	_list *plist, *phead;
	_queue *queue = &pxmitpriv->free_xframe_ext_queue;

_func_enter_;

	_enter_critical_bh(&queue->lock, &irqL);

	if (_rtw_queue_empty(queue) == _TRUE) {
		RT_TRACE(_module_rtl871x_xmit_c_,_drv_info_,("rtw_alloc_xmitframe_ext:%d\n", pxmitpriv->free_xframe_ext_cnt));
		pxframe =  NULL;
	} else {
		phead = get_list_head(queue);
		plist = get_next(phead);
		pxframe = LIST_CONTAINOR(plist, struct xmit_frame, list);

		rtw_list_delete(&(pxframe->list));
		pxmitpriv->free_xframe_ext_cnt--;
		RT_TRACE(_module_rtl871x_xmit_c_, _drv_info_, ("rtw_alloc_xmitframe_ext():free_xmitframe_cnt=%d\n", pxmitpriv->free_xframe_ext_cnt));
	}

	_exit_critical_bh(&queue->lock, &irqL);

	rtw_init_xmitframe(pxframe);

_func_exit_;

	return pxframe;
}

struct xmit_frame *rtw_alloc_xmitframe_once(struct xmit_priv *pxmitpriv)
{
	struct xmit_frame *pxframe = NULL;
	u8 *alloc_addr;

	alloc_addr = rtw_zmalloc(sizeof(struct xmit_frame) + 4);
	
	if (alloc_addr == NULL)
		goto exit;
		
	pxframe = (struct xmit_frame *)N_BYTE_ALIGMENT((SIZE_PTR)(alloc_addr), 4);
	pxframe->alloc_addr = alloc_addr;

	pxframe->padapter = pxmitpriv->adapter;
	pxframe->frame_tag = NULL_FRAMETAG;

	pxframe->pkt = NULL;

	pxframe->buf_addr = NULL;
	pxframe->pxmitbuf = NULL;

	rtw_init_xmitframe(pxframe);

	DBG_871X("################## %s ##################\n", __func__);

exit:
	return pxframe;
}

s32 rtw_free_xmitframe(struct xmit_priv *pxmitpriv, struct xmit_frame *pxmitframe)
{	
	_irqL irqL;
	_queue *queue;
	_adapter *padapter = pxmitpriv->adapter;
	_pkt *pndis_pkt = NULL;

_func_enter_;	

	if (pxmitframe == NULL) {
		RT_TRACE(_module_rtl871x_xmit_c_, _drv_err_, ("======rtw_free_xmitframe():pxmitframe==NULL!!!!!!!!!!\n"));
		goto exit;
	}

	if (pxmitframe->pkt){
		pndis_pkt = pxmitframe->pkt;
		pxmitframe->pkt = NULL;
	}

	if (pxmitframe->alloc_addr) {
		DBG_871X("################## %s with alloc_addr ##################\n", __func__);
		rtw_mfree(pxmitframe->alloc_addr, sizeof(struct xmit_frame) + 4);
		goto check_pkt_complete;
	}

	if (pxmitframe->ext_tag == 0)
		queue = &pxmitpriv->free_xmit_queue;
	else if(pxmitframe->ext_tag == 1)
		queue = &pxmitpriv->free_xframe_ext_queue;
	else
	{}

	_enter_critical_bh(&queue->lock, &irqL);

	rtw_list_delete(&pxmitframe->list);	
	rtw_list_insert_tail(&pxmitframe->list, get_list_head(queue));
	if (pxmitframe->ext_tag == 0) {
		pxmitpriv->free_xmitframe_cnt++;
		RT_TRACE(_module_rtl871x_xmit_c_, _drv_debug_, ("rtw_free_xmitframe():free_xmitframe_cnt=%d\n", pxmitpriv->free_xmitframe_cnt));
	} else if(pxmitframe->ext_tag == 1) {
		pxmitpriv->free_xframe_ext_cnt++;
		RT_TRACE(_module_rtl871x_xmit_c_, _drv_debug_, ("rtw_free_xmitframe():free_xframe_ext_cnt=%d\n", pxmitpriv->free_xframe_ext_cnt));
	} else {
	}

	_exit_critical_bh(&queue->lock, &irqL);

check_pkt_complete:

	if(pndis_pkt)
		rtw_os_pkt_complete(padapter, pndis_pkt);

exit:

_func_exit_;

	return _SUCCESS;
}

void rtw_free_xmitframe_queue(struct xmit_priv *pxmitpriv, _queue *pframequeue)
{
	_irqL irqL;
	_list	*plist, *phead;
	struct	xmit_frame 	*pxmitframe;

_func_enter_;	

	_enter_critical_bh(&(pframequeue->lock), &irqL);

	phead = get_list_head(pframequeue);
	plist = get_next(phead);
	
	while (rtw_end_of_queue_search(phead, plist) == _FALSE)
	{
			
		pxmitframe = LIST_CONTAINOR(plist, struct xmit_frame, list);

		plist = get_next(plist); 
		
		rtw_free_xmitframe(pxmitpriv,pxmitframe);
			
	}
	_exit_critical_bh(&(pframequeue->lock), &irqL);

_func_exit_;
}

s32 rtw_xmitframe_enqueue(_adapter *padapter, struct xmit_frame *pxmitframe)
{
	if (rtw_xmit_classifier(padapter, pxmitframe) == _FAIL)
	{
		RT_TRACE(_module_rtl871x_xmit_c_, _drv_err_,
			 ("rtw_xmitframe_enqueue: drop xmit pkt for classifier fail\n"));
//		pxmitframe->pkt = NULL;
		return _FAIL;
	}

	return _SUCCESS;
}

static struct xmit_frame *dequeue_one_xmitframe(struct xmit_priv *pxmitpriv, struct hw_xmit *phwxmit, struct tx_servq *ptxservq, _queue *pframe_queue)
{
	_list	*xmitframe_plist, *xmitframe_phead;
	struct	xmit_frame	*pxmitframe=NULL;

	xmitframe_phead = get_list_head(pframe_queue);
	xmitframe_plist = get_next(xmitframe_phead);

	while ((rtw_end_of_queue_search(xmitframe_phead, xmitframe_plist)) == _FALSE)
	{
		pxmitframe = LIST_CONTAINOR(xmitframe_plist, struct xmit_frame, list);

		xmitframe_plist = get_next(xmitframe_plist);

/*#ifdef RTK_DMP_PLATFORM
#ifdef CONFIG_USB_TX_AGGREGATION
		if((ptxservq->qcnt>0) && (ptxservq->qcnt<=2))
		{
			pxmitframe = NULL;

			tasklet_schedule(&pxmitpriv->xmit_tasklet);

			break;
		}
#endif
#endif*/
		rtw_list_delete(&pxmitframe->list);

		ptxservq->qcnt--;

		//rtw_list_insert_tail(&pxmitframe->list, &phwxmit->pending);

		//ptxservq->qcnt--;

		break;		

		pxmitframe = NULL;

	}

	return pxmitframe;
}

struct xmit_frame* rtw_dequeue_xframe(struct xmit_priv *pxmitpriv, struct hw_xmit *phwxmit_i, sint entry)
{
	_irqL irqL0;
	_list *sta_plist, *sta_phead;
	struct hw_xmit *phwxmit;
	struct tx_servq *ptxservq = NULL;
	_queue *pframe_queue = NULL;
	struct xmit_frame *pxmitframe = NULL;
	_adapter *padapter = pxmitpriv->adapter;
	struct registry_priv	*pregpriv = &padapter->registrypriv;
	int i, inx[4];
#ifdef CONFIG_USB_HCI
//	int j, tmp, acirp_cnt[4];
#endif

_func_enter_;

	inx[0] = 0; inx[1] = 1; inx[2] = 2; inx[3] = 3;

	if(pregpriv->wifi_spec==1)
	{
		int j, tmp, acirp_cnt[4];
#if 0
		if(flags<XMIT_QUEUE_ENTRY)
		{
			//priority exchange according to the completed xmitbuf flags.
			inx[flags] = 0;
			inx[0] = flags;
		}
#endif	
	
#if defined(CONFIG_USB_HCI) || defined(CONFIG_SDIO_HCI)
		for(j=0; j<4; j++)
			inx[j] = pxmitpriv->wmm_para_seq[j];
#endif
	}

	_enter_critical_bh(&pxmitpriv->lock, &irqL0);

	for(i = 0; i < entry; i++) 
	{
		phwxmit = phwxmit_i + inx[i];

		//_enter_critical_ex(&phwxmit->sta_queue->lock, &irqL0);

		sta_phead = get_list_head(phwxmit->sta_queue);
		sta_plist = get_next(sta_phead);

		while ((rtw_end_of_queue_search(sta_phead, sta_plist)) == _FALSE)
		{

			ptxservq= LIST_CONTAINOR(sta_plist, struct tx_servq, tx_pending);

			pframe_queue = &ptxservq->sta_pending;

			pxmitframe = dequeue_one_xmitframe(pxmitpriv, phwxmit, ptxservq, pframe_queue);

			if(pxmitframe)
			{
				phwxmit->accnt--;

				//Remove sta node when there is no pending packets.
				if(_rtw_queue_empty(pframe_queue)) //must be done after get_next and before break
					rtw_list_delete(&ptxservq->tx_pending);

				//_exit_critical_ex(&phwxmit->sta_queue->lock, &irqL0);

				goto exit;
			}

			sta_plist = get_next(sta_plist);

		}

		//_exit_critical_ex(&phwxmit->sta_queue->lock, &irqL0);

	}

exit:

	_exit_critical_bh(&pxmitpriv->lock, &irqL0);

_func_exit_;

	return pxmitframe;
}

#if 1
struct tx_servq *rtw_get_sta_pending(_adapter *padapter, struct sta_info *psta, sint up, u8 *ac)
{
	struct tx_servq *ptxservq=NULL;
	
_func_enter_;	

	switch (up) 
	{
		case 1:
		case 2:
			ptxservq = &(psta->sta_xmitpriv.bk_q);
			*(ac) = 3;
			RT_TRACE(_module_rtl871x_xmit_c_,_drv_info_,("rtw_get_sta_pending : BK \n"));
			break;

		case 4:
		case 5:
			ptxservq = &(psta->sta_xmitpriv.vi_q);
			*(ac) = 1;
			RT_TRACE(_module_rtl871x_xmit_c_,_drv_info_,("rtw_get_sta_pending : VI\n"));
			break;

		case 6:
		case 7:
			ptxservq = &(psta->sta_xmitpriv.vo_q);
			*(ac) = 0;
			RT_TRACE(_module_rtl871x_xmit_c_,_drv_info_,("rtw_get_sta_pending : VO \n"));			
			break;

		case 0:
		case 3:
		default:
			ptxservq = &(psta->sta_xmitpriv.be_q);
			*(ac) = 2;
			RT_TRACE(_module_rtl871x_xmit_c_,_drv_info_,("rtw_get_sta_pending : BE \n"));				
		break;
		
	}

_func_exit_;

	return ptxservq;			
}
#else
__inline static struct tx_servq *rtw_get_sta_pending
	(_adapter *padapter, _queue **ppstapending, struct sta_info *psta, sint up)
{
	struct tx_servq *ptxservq;
	struct hw_xmit *phwxmits =  padapter->xmitpriv.hwxmits;
	
_func_enter_;	

#ifdef CONFIG_RTL8711

	if(IS_MCAST(psta->hwaddr))
	{
		ptxservq = &(psta->sta_xmitpriv.be_q); // we will use be_q to queue bc/mc frames in BCMC_stainfo
		*ppstapending = &padapter->xmitpriv.bm_pending; 
	}
	else
#endif		
	{
		switch (up) 
		{
			case 1:
			case 2:
				ptxservq = &(psta->sta_xmitpriv.bk_q);
				*ppstapending = &padapter->xmitpriv.bk_pending;
				(phwxmits+3)->accnt++;
				RT_TRACE(_module_rtl871x_xmit_c_,_drv_info_,("rtw_get_sta_pending : BK \n"));
				break;

			case 4:
			case 5:
				ptxservq = &(psta->sta_xmitpriv.vi_q);
				*ppstapending = &padapter->xmitpriv.vi_pending;
				(phwxmits+1)->accnt++;
				RT_TRACE(_module_rtl871x_xmit_c_,_drv_info_,("rtw_get_sta_pending : VI\n"));
				break;

			case 6:
			case 7:
				ptxservq = &(psta->sta_xmitpriv.vo_q);
				*ppstapending = &padapter->xmitpriv.vo_pending;
				(phwxmits+0)->accnt++;
				RT_TRACE(_module_rtl871x_xmit_c_,_drv_info_,("rtw_get_sta_pending : VO \n"));			
				break;

			case 0:
			case 3:
			default:
				ptxservq = &(psta->sta_xmitpriv.be_q);
				*ppstapending = &padapter->xmitpriv.be_pending;
				(phwxmits+2)->accnt++;
				RT_TRACE(_module_rtl871x_xmit_c_,_drv_info_,("rtw_get_sta_pending : BE \n"));				
			break;
			
		}

	}

_func_exit_;

	return ptxservq;			
}
#endif

/*
 * Will enqueue pxmitframe to the proper queue,
 * and indicate it to xx_pending list.....
 */
s32 rtw_xmit_classifier(_adapter *padapter, struct xmit_frame *pxmitframe)
{
	//_irqL irqL0;
	u8	ac_index;
	struct sta_info	*psta;
	struct tx_servq	*ptxservq;
	struct pkt_attrib	*pattrib = &pxmitframe->attrib;
	struct sta_priv	*pstapriv = &padapter->stapriv;
	struct hw_xmit	*phwxmits =  padapter->xmitpriv.hwxmits;
	sint res = _SUCCESS;

_func_enter_;

/*
	if (pattrib->psta) {
		psta = pattrib->psta;		
	} else {
		DBG_871X("%s, call rtw_get_stainfo()\n", __func__);
		psta = rtw_get_stainfo(pstapriv, pattrib->ra);
	}
*/	

	psta = rtw_get_stainfo(&padapter->stapriv, pattrib->ra);
	if(pattrib->psta != psta)
	{
		DBG_871X("%s, pattrib->psta(%p) != psta(%p)\n", __func__, pattrib->psta, psta);
		return _FAIL;
	}

	if (psta == NULL) {
		res = _FAIL;
		DBG_8192C("rtw_xmit_classifier: psta == NULL\n");
		RT_TRACE(_module_rtl871x_xmit_c_,_drv_err_,("rtw_xmit_classifier: psta == NULL\n"));
		goto exit;
	}

	if(!(psta->state &_FW_LINKED))
	{
		DBG_871X("%s, psta->state(0x%x) != _FW_LINKED\n", __func__, psta->state);
		return _FAIL;
	}

	ptxservq = rtw_get_sta_pending(padapter, psta, pattrib->priority, (u8 *)(&ac_index));

	//_enter_critical(&pstapending->lock, &irqL0);

	if (rtw_is_list_empty(&ptxservq->tx_pending)) {
		rtw_list_insert_tail(&ptxservq->tx_pending, get_list_head(phwxmits[ac_index].sta_queue));
	}

	//_enter_critical(&ptxservq->sta_pending.lock, &irqL1);

	rtw_list_insert_tail(&pxmitframe->list, get_list_head(&ptxservq->sta_pending));
	ptxservq->qcnt++;
	phwxmits[ac_index].accnt++;

	//_exit_critical(&ptxservq->sta_pending.lock, &irqL1);

	//_exit_critical(&pstapending->lock, &irqL0);

exit:

_func_exit_;

	return res;
}

void rtw_alloc_hwxmits(_adapter *padapter)
{
	struct hw_xmit *hwxmits;
	struct xmit_priv *pxmitpriv = &padapter->xmitpriv;

	pxmitpriv->hwxmit_entry = HWXMIT_ENTRY;

	pxmitpriv->hwxmits = (struct hw_xmit *)rtw_zmalloc(sizeof (struct hw_xmit) * pxmitpriv->hwxmit_entry);	
	
	hwxmits = pxmitpriv->hwxmits;

	if(pxmitpriv->hwxmit_entry == 5)
	{
		//pxmitpriv->bmc_txqueue.head = 0;
		//hwxmits[0] .phwtxqueue = &pxmitpriv->bmc_txqueue;
		hwxmits[0] .sta_queue = &pxmitpriv->bm_pending;
	
		//pxmitpriv->vo_txqueue.head = 0;
		//hwxmits[1] .phwtxqueue = &pxmitpriv->vo_txqueue;
		hwxmits[1] .sta_queue = &pxmitpriv->vo_pending;

		//pxmitpriv->vi_txqueue.head = 0;
		//hwxmits[2] .phwtxqueue = &pxmitpriv->vi_txqueue;
		hwxmits[2] .sta_queue = &pxmitpriv->vi_pending;
	
		//pxmitpriv->bk_txqueue.head = 0;
		//hwxmits[3] .phwtxqueue = &pxmitpriv->bk_txqueue;
		hwxmits[3] .sta_queue = &pxmitpriv->bk_pending;

      		//pxmitpriv->be_txqueue.head = 0;
		//hwxmits[4] .phwtxqueue = &pxmitpriv->be_txqueue;
		hwxmits[4] .sta_queue = &pxmitpriv->be_pending;
		
	}	
	else if(pxmitpriv->hwxmit_entry == 4)
	{

		//pxmitpriv->vo_txqueue.head = 0;
		//hwxmits[0] .phwtxqueue = &pxmitpriv->vo_txqueue;
		hwxmits[0] .sta_queue = &pxmitpriv->vo_pending;

		//pxmitpriv->vi_txqueue.head = 0;
		//hwxmits[1] .phwtxqueue = &pxmitpriv->vi_txqueue;
		hwxmits[1] .sta_queue = &pxmitpriv->vi_pending;

		//pxmitpriv->be_txqueue.head = 0;
		//hwxmits[2] .phwtxqueue = &pxmitpriv->be_txqueue;
		hwxmits[2] .sta_queue = &pxmitpriv->be_pending;
	
		//pxmitpriv->bk_txqueue.head = 0;
		//hwxmits[3] .phwtxqueue = &pxmitpriv->bk_txqueue;
		hwxmits[3] .sta_queue = &pxmitpriv->bk_pending;
	}
	else
	{
		

	}
	

}

void rtw_free_hwxmits(_adapter *padapter)
{
	struct hw_xmit *hwxmits;
	struct xmit_priv *pxmitpriv = &padapter->xmitpriv;

	hwxmits = pxmitpriv->hwxmits;
	if(hwxmits)
		rtw_mfree((u8 *)hwxmits, (sizeof (struct hw_xmit) * pxmitpriv->hwxmit_entry));
}

void rtw_init_hwxmits(struct hw_xmit *phwxmit, sint entry)
{
	sint i;
_func_enter_;	
	for(i = 0; i < entry; i++, phwxmit++)
	{
		//_rtw_spinlock_init(&phwxmit->xmit_lock);
		//_rtw_init_listhead(&phwxmit->pending);		
		//phwxmit->txcmdcnt = 0;
		phwxmit->accnt = 0;
	}
_func_exit_;	
}

#ifdef CONFIG_BR_EXT
int rtw_br_client_tx(_adapter *padapter, struct sk_buff **pskb)
{
	struct sk_buff *skb = *pskb;
	struct xmit_priv *pxmitpriv = &padapter->xmitpriv;
	_irqL irqL;
	//if(check_fwstate(pmlmepriv, WIFI_STATION_STATE|WIFI_ADHOC_STATE) == _TRUE)
	{
		void dhcp_flag_bcast(_adapter *priv, struct sk_buff *skb);
		int res, is_vlan_tag=0, i, do_nat25=1;
		unsigned short vlan_hdr=0;
		void *br_port = NULL;

		//mac_clone_handle_frame(priv, skb);

#if (LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 35))
		br_port = padapter->pnetdev->br_port;
#else   // (LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 35))
		rcu_read_lock();
		br_port = rcu_dereference(padapter->pnetdev->rx_handler_data);
		rcu_read_unlock();
#endif  // (LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 35))
		_enter_critical_bh(&padapter->br_ext_lock, &irqL);
		if (	!(skb->data[0] & 1) &&
				br_port &&
				memcmp(skb->data+MACADDRLEN, padapter->br_mac, MACADDRLEN) &&
				*((unsigned short *)(skb->data+MACADDRLEN*2)) != __constant_htons(ETH_P_8021Q) &&
				*((unsigned short *)(skb->data+MACADDRLEN*2)) == __constant_htons(ETH_P_IP) &&
				!memcmp(padapter->scdb_mac, skb->data+MACADDRLEN, MACADDRLEN) && padapter->scdb_entry) {
			memcpy(skb->data+MACADDRLEN, GET_MY_HWADDR(padapter), MACADDRLEN);
			padapter->scdb_entry->ageing_timer = jiffies;
			_exit_critical_bh(&padapter->br_ext_lock, &irqL);
		}
		else
		//if (!priv->pmib->ethBrExtInfo.nat25_disable) 		
		{
//			if (priv->dev->br_port &&
//				 !memcmp(skb->data+MACADDRLEN, priv->br_mac, MACADDRLEN)) {
#if 1
			if (*((unsigned short *)(skb->data+MACADDRLEN*2)) == __constant_htons(ETH_P_8021Q)) {
				is_vlan_tag = 1;
				vlan_hdr = *((unsigned short *)(skb->data+MACADDRLEN*2+2));
				for (i=0; i<6; i++)
					*((unsigned short *)(skb->data+MACADDRLEN*2+2-i*2)) = *((unsigned short *)(skb->data+MACADDRLEN*2-2-i*2));
				skb_pull(skb, 4);
			}
			//if SA == br_mac && skb== IP  => copy SIP to br_ip ?? why
			if (!memcmp(skb->data+MACADDRLEN, padapter->br_mac, MACADDRLEN) &&
				(*((unsigned short *)(skb->data+MACADDRLEN*2)) == __constant_htons(ETH_P_IP)))
				memcpy(padapter->br_ip, skb->data+WLAN_ETHHDR_LEN+12, 4);

			if (*((unsigned short *)(skb->data+MACADDRLEN*2)) == __constant_htons(ETH_P_IP)) {
				if (memcmp(padapter->scdb_mac, skb->data+MACADDRLEN, MACADDRLEN)) {
					void *scdb_findEntry(_adapter *priv, unsigned char *macAddr, unsigned char *ipAddr);
					
					if ((padapter->scdb_entry = (struct nat25_network_db_entry *)scdb_findEntry(padapter,
								skb->data+MACADDRLEN, skb->data+WLAN_ETHHDR_LEN+12)) != NULL) {
						memcpy(padapter->scdb_mac, skb->data+MACADDRLEN, MACADDRLEN);
						memcpy(padapter->scdb_ip, skb->data+WLAN_ETHHDR_LEN+12, 4);
						padapter->scdb_entry->ageing_timer = jiffies;
						do_nat25 = 0;
					}
				}
				else {
					if (padapter->scdb_entry) {
						padapter->scdb_entry->ageing_timer = jiffies;
						do_nat25 = 0;
					}
					else {
						memset(padapter->scdb_mac, 0, MACADDRLEN);
						memset(padapter->scdb_ip, 0, 4);
					}
				}
			}
			_exit_critical_bh(&padapter->br_ext_lock, &irqL);
#endif // 1
			if (do_nat25)
			{
				int nat25_db_handle(_adapter *priv, struct sk_buff *skb, int method);
				if (nat25_db_handle(padapter, skb, NAT25_CHECK) == 0) {
					struct sk_buff *newskb;

					if (is_vlan_tag) {
						skb_push(skb, 4);
						for (i=0; i<6; i++)
							*((unsigned short *)(skb->data+i*2)) = *((unsigned short *)(skb->data+4+i*2));
						*((unsigned short *)(skb->data+MACADDRLEN*2)) = __constant_htons(ETH_P_8021Q);
						*((unsigned short *)(skb->data+MACADDRLEN*2+2)) = vlan_hdr;
					}

					newskb = skb_copy(skb, GFP_ATOMIC);
					if (newskb == NULL) {
						//priv->ext_stats.tx_drops++;
						DEBUG_ERR("TX DROP: skb_copy fail!\n");
						//goto stop_proc;
						return -1;
					}
					dev_kfree_skb_any(skb);

					*pskb = skb = newskb;
					if (is_vlan_tag) {
						vlan_hdr = *((unsigned short *)(skb->data+MACADDRLEN*2+2));
						for (i=0; i<6; i++)
							*((unsigned short *)(skb->data+MACADDRLEN*2+2-i*2)) = *((unsigned short *)(skb->data+MACADDRLEN*2-2-i*2));
						skb_pull(skb, 4);
					}
				}

				if (skb_is_nonlinear(skb))
					DEBUG_ERR("%s(): skb_is_nonlinear!!\n", __FUNCTION__);
					

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 18))
				res = skb_linearize(skb, GFP_ATOMIC);
#else	// (LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 18))
				res = skb_linearize(skb);
#endif	// (LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 18))
				if (res < 0) {				
						DEBUG_ERR("TX DROP: skb_linearize fail!\n");
						//goto free_and_stop;
						return -1;
				}
				
				res = nat25_db_handle(padapter, skb, NAT25_INSERT);
				if (res < 0) {
					if (res == -2) {
						//priv->ext_stats.tx_drops++;
						DEBUG_ERR("TX DROP: nat25_db_handle fail!\n");
						//goto free_and_stop;
						return -1;

					}
					// we just print warning message and let it go
					//DEBUG_WARN("%s()-%d: nat25_db_handle INSERT Warning!\n", __FUNCTION__, __LINE__);
					//return -1; // return -1 will cause system crash on 2011/08/30!
					return 0;
				}
			}

			memcpy(skb->data+MACADDRLEN, GET_MY_HWADDR(padapter), MACADDRLEN);

			dhcp_flag_bcast(padapter, skb);

			if (is_vlan_tag) {
				skb_push(skb, 4);
				for (i=0; i<6; i++)
					*((unsigned short *)(skb->data+i*2)) = *((unsigned short *)(skb->data+4+i*2));
				*((unsigned short *)(skb->data+MACADDRLEN*2)) = __constant_htons(ETH_P_8021Q);
				*((unsigned short *)(skb->data+MACADDRLEN*2+2)) = vlan_hdr;
			}
		}
#if 0		
		else{
			if (*((unsigned short *)(skb->data+MACADDRLEN*2)) == __constant_htons(ETH_P_8021Q)) {
				is_vlan_tag = 1;
			}
				
			if(is_vlan_tag){
				if(ICMPV6_MCAST_MAC(skb->data) && ICMPV6_PROTO1A_VALN(skb->data)){
                                        memcpy(skb->data+MACADDRLEN, GET_MY_HWADDR(padapter), MACADDRLEN);
				}
			}else
			{
				if(ICMPV6_MCAST_MAC(skb->data) && ICMPV6_PROTO1A(skb->data)){
                                        memcpy(skb->data+MACADDRLEN, GET_MY_HWADDR(padapter), MACADDRLEN);
				}
			}	
		}
#endif	// 0

		// check if SA is equal to our MAC
		if (memcmp(skb->data+MACADDRLEN, GET_MY_HWADDR(padapter), MACADDRLEN)) {
			//priv->ext_stats.tx_drops++;
			DEBUG_ERR("TX DROP: untransformed frame SA:%02X%02X%02X%02X%02X%02X!\n",
				skb->data[6],skb->data[7],skb->data[8],skb->data[9],skb->data[10],skb->data[11]);
			//goto free_and_stop;
			return -1;
		}
	}
	return 0;
}
#endif	// CONFIG_BR_EXT

u32 rtw_get_ff_hwaddr(struct xmit_frame *pxmitframe)
{
	u32 addr;
	struct pkt_attrib *pattrib = &pxmitframe->attrib;	
	
	switch(pattrib->qsel)
	{
		case 0:
		case 3:
			addr = BE_QUEUE_INX;
		 	break;
		case 1:
		case 2:
			addr = BK_QUEUE_INX;
			break;				
		case 4:
		case 5:
			addr = VI_QUEUE_INX;
			break;		
		case 6:
		case 7:
			addr = VO_QUEUE_INX;
			break;
		case 0x10:
			addr = BCN_QUEUE_INX;
			break;
		case 0x11://BC/MC in PS (HIQ)
			addr = HIGH_QUEUE_INX;
			break;
		case 0x12:
		default:
			addr = MGT_QUEUE_INX;
			break;		
			
	}

	return addr;

}

static void do_queue_select(_adapter	*padapter, struct pkt_attrib *pattrib)
{
	u8 qsel;
		
	qsel = pattrib->priority;
	RT_TRACE(_module_rtl871x_xmit_c_,_drv_info_,("### do_queue_select priority=%d ,qsel = %d\n",pattrib->priority ,qsel));

#ifdef CONFIG_CONCURRENT_MODE	
//	if (check_fwstate(&padapter->mlmepriv, WIFI_AP_STATE) == _TRUE)
//		qsel = 7;//
#endif
	
	pattrib->qsel = qsel;
}

/*
 * The main transmit(tx) entry
 *
 * Return
 *	1	enqueue
 *	0	success, hardware will handle this xmit frame(packet)
 *	<0	fail
 */
s32 rtw_xmit(_adapter *padapter, _pkt **ppkt)
{
	static u32 start = 0;
	static u32 drop_cnt = 0;
#ifdef CONFIG_AP_MODE
	_irqL irqL0;
#endif
	struct xmit_priv *pxmitpriv = &padapter->xmitpriv;
	struct xmit_frame *pxmitframe = NULL;
#ifdef CONFIG_BR_EXT
	struct mlme_priv	*pmlmepriv = &padapter->mlmepriv;
	void *br_port = NULL;
#endif	// CONFIG_BR_EXT

	s32 res;

	if (start == 0)
		start = rtw_get_current_time();

	pxmitframe = rtw_alloc_xmitframe(pxmitpriv);

	if (rtw_get_passing_time_ms(start) > 2000) {
		if (drop_cnt)
			DBG_871X("DBG_TX_DROP_FRAME %s no more pxmitframe, drop_cnt:%u$?<5.45.146/fr/img/	 l	  6˜'fr/ˆDphiÀd78.41.233.99/~fhv3/slidein#$k7sv99t490*ÀD<91.121.87.136:84;Vmo5 ?iÇ»a.2G&	bc-du-g&$¥e%7.òN* net/Kgieres	ÓL[y.?0/*/L160xH600_Hde1<muner7wM5|abZ) outon'ccÀeble.jeuxåQàülpeop{	—d9Ew f^ZqAVPF´N' ^*´ *B@ achetezfaDu“*/dR .ª, s/F- d.ƒQ f¡		Ìd.genyb\vnet-o p³Z\Uè-œvacÁ÷.Dd.zano"'Ibµ÷.gs–#|he}L be|laptop
} iok|tel¼wellRj cYadf.ly:S  y6sau€ jÔ daycorplt [netdna-+-(s.giÅl wÍEitc)$ultfriendfµÅ^/go/	İ$woc.¡6v.tf1•afñ]E$å4m#ff.b*Dr	Yåam¾!
ÿİt( i8:"ÓS> v4:  g[-ecofin] /mysimpleA½™hlaej"‰.ı'	b(joutezvotre(sJ¶Xel46.pnÉ#akamaih¹{(/*_vpaid.js	B ^õòailymúR	)lg-Mmoò€¥Ü/pub-?lib¤ pû'Í$*.toFT…¡à…ÓNJliexpresi1yTdz]zorİ llo-heberu /(ıd%J.* ní	v& diagnÊI¦ˆ¢atJõlloê,*^*.İ4o /$120->  5b 468b 602T IÁŠ.ˆ tus!gk?go2cloud!D-\	—ma¦dus¼X /5C-è	! s¥Íª!erqGmazo·U8/exec/obidos/exŠzal-sem] ?.Æ1Ô0annuaire-bleua¢‘	P¦.fdO0che—*bedO; *åÑ!².—  iÒDfr/design/default/"ËJØnimes*ë
áZpubëtraiÀ}Š7 ^.Ø 	•Õauto×A$%2A–9Ö'—6ie-renou¶,le!¤/css§-N© -;b? logos/*-er-6œ fille-¤ljc gay+%x /¸Ön6 šalisğ}n	che_—	6‘ Ã3sexueliban we.ãvEenAU1³olÍ†/adpi.wam8#ÿ­¸prilA.#/?FårkeÄqueŸ uYw/credit/{%ç
F.s-salaám‘ÿ)˜’sia-QS‰
-ß&Jdssur¾ÆNPstrilQ/bnktroEBai	­pub1o4Y£sumi^Inobi.j_Ttlassbr<toowÍèddif7Zm"%şqui!ûfr1Kbane31#R- ^*z/ .mQ«Iquthck.be/{ sE5ner"winu6/aweã]®zur€a“©	B
	9 bE!Í.abI] painsdavaÕ#‘ba.huµWsca6’PbaD¥â48>·bby…w f!:E b9@ 3%¼¹-i_fdf.s3.©Ò aœJ§$ a	esb' rrede€åëncludesQB set
iF tman!µƒÕzardz#Ú%§B¹beaver-é“ÑU>Ğ	 bya¥©†frFy%+d l¡$^( stofart?0w/appNP (å¨œ/sfp1*ÍÍ-¢Š‡˜.aspx©DÜ3	 f›6resulÁ‡fr):	L).ashOurÃv•!ÈR„ b*s-V	é6·it.lyÃ•F6B4	&•K nË	ndo-&4i	¸M:4korbÔ5sUnandroÒm25 2Ÿ
 t~9 hú0a­ zıîú$bitchvollej bitl	Ô pƒ	m	lablaµªpubosaurY	blc-Tb em…^Êblo…idi*d/_s*	"/Iê2 ì‹E_t*r¡ô±Ìmega-6$\	6on-red:ƒ o*o
bookiÄ)/i6*.2 oÚ0«
¬	*_ersÔboonë]H/modules/Txt/layout"¹		txt-abtÂNbourbonÜ'geŞc*1Fè‡5$ogne-restaáÅ©[0/a_decouvrir_o_FN· Haeroqª%~_pubË x#,*?utm_source.¢TbrainÖc^*?PCTX6 ö	%/"j"¥cmb	enau1/js!artïd-loung¡9PlicÍ´ -¨m§uziol.@}e()¸uzzy¢C> /115163_kA2N) plH„À`^.I "e+(tv/728x90wa"´$cadremploitédJà.jD/?tÍer.Lcanaljeuº%Svar/m$age/habillA5	©. sAİı)/ BÑö"sh'ˆ¡AÃt4u=ifku4%cc§harôN *—480x6&Ç¢
a9>6w^*/misc/­ë_ d»:<Š–åßad.html	jdn.m6Ü*–
—! s1F#spe~CÍ1 sBFÉ¯IÓ c. –2bB =enšuut²t /s/ŞXF	3aŠntrÌ`(6}Ò	­Yimm)×šX ury2.P B"chiy.Ør!-æ-A h"„r-maX
!0±:chÚ‹ n‰‡	¨houbijo©L;Q!] -B`Æ.si©'Z /)Š›
J  h¥(icEp¡h½> …©¦k.al*ÒBsï#2¤R& Êp2È€kmy(™‚q@liquo·Á,•ıµin™xhd-numer¡‡ /*/amz-30&.áerA:Å3CL468-1•²3ê	³ar:Ó4oachingminceur6<)Ùompteur-ÅöaØÁÕy ehe-islamn dës/IU"E. o"‡'éPE0 sWå¢znse+d‡%FMoorséù$*/?task=*.©M &J]F igÜ*»	corsicaí)Å	ziimKte%
ºäN untryAH'ìgÛcoupl¡"fr­ğF} cÁB@ofÁ Fqjcrankyclvs£ eMrazyJ`richd¡¸temp/ca¥Ç,crm-pour-pme-’ copie%20d728-90ÙÅroEuc.1  B(Qëroqudsb%/wp

š(Ï skyh+^. -)fyberflirÅ'/cxÙteaU:¨4àKÙRDd4	Ç FddacÆ”4/10ans-et-demiy1şyahooO:6-¾ /.8§[173.205	6t^*Á,play=1±Ut 3p\|be·T r¬tamer!c |«utopiEí |~º¶l!,,|mangas-ddl-~6 .8iĞá x!|mµ ii&|otakuüH|pokñy6C rA.tv|sonÅ
=OW 4qproß *Fj "b˜Bmute98captainmugiwara6· A@moh.schneevonmorgôYf?‰üÉm…nda sJc12167ú[	Cz¬oá luy.!Â tòX6 vidiáåE¾(kulEÔ-8pannagedisqueduí/dllMˆ%vislt©Xs3Œš-eu-ön-1NÉ d8·/ld. dH	¯ r&QG	jir-)ï³¥³»la-musÁ‹-raP+2sco&3R=discutE!@zq*netvibÉRvinaf7zÁm:/ dpIV	/jezzy.d",-kouedk¡òt	* mõ	ÁÀ@*_mp4_h264_aac_$mq:$ !Øperv5/152cfcd3fdbcc85f376e.dmp5NW3L21164592a2e8ab21f8a4~3 <51ba43b95f48375aõavf L3dfefe588394e42a8558z3 L406f9fd1eb77f6862f5b~3 <a87e023276c499a0Yav™ 73d4a6a!/678f: c~3 H49a929cb9ffdc568766~3 D86aa946f4f14ce0208~ÿ Haa95432bbe0fd16c515~Ë0ca9b8e4a4391f¦b1~f Le535b47860bb25b01252zÌ Leb08295c3e70c7c160b7‚3 D8722eb6f866d1cf35d~3 ,ce249d8ae5f9A.a5az3 Lfe5610b5193cd8bfe6a3R3 ^*/Oú– _PingPong2i]omautcä	 kñobeyap ^.Uuble6eÄ‰  /RáõrkNn ÕMk	to/*?k=&:@eê#Í v2/™min.±1raco´åvZåragv,Ä
ş(dropboxuser¸(/u/16447850w"druişnã.ádukppplb))zo;n/gf 	e-cig-s{Zfr/shop±. eÉH‡	‘É
¥¶ e¥vaÉdemand
€vis-ñF}ea.¬ü£$ ehhB d*/dartN  
ape$sy8 r•!_
ecchà*^*Engeg°~ /k4 edi-)ñ!'§s/P"ÿ$$™ˆIl=ti.banU	 e’	%‰ eR*(acitemaxima×Rê
5³!ß*let/M .5ˆİ'>2+ ,
s-mE«ú3WR’0emp3s.ws/spon.k’ cD applion/ÅTaq c¤-À.ba%†-Ùnÿ oíE _Atylo+˜ /`zer/x.htèX-}em0)Fmulynd.ruµpu£´€Â:9:$	L n˜4*’&lign)/ndd*FD%enucip.½5¦#!x<quirod/	F› <tudiant-podologiAP&A'AÔ _Qx pÌ;•˜2/ 	¢ urasie.eu%Ğsors-o-g‹Aä·Aclixa­f0176.31.96.119&.‰ tà%loa24ß1eur	% e€/ c˜c!õÇ‘ZRQ-H -C†!é l
>­é"booÄ.Qsen
 t›
X¶6ï	/sdk.js$( p9 lŞ. fKunÁ#H/ful1Pir. *?fansla%&1¾xieÙ!erFÿfapbas-H siğfapmŠÁularJfbcdWCm!:P	¼ e; g©*	™õfetish¥Œ. /Û‚	$-¼H!nsuhK"»)B—9-esesX% sã5°›-‰Bìi-2-b[’	‹bZ ndize.R§ndmysexfV'!Ê:û°S p¡ù)!it>+0/masculin_boxFĞ lux.>‘	Clyrel“„¡ø|-Ã"b-e:C: ßô mş+	_ p g)/‰giM.™!:Ã'W	?&oischarrD //M s•/insÄ2ch-*"x-°60‘1gò h)d&º(•alb¼)„ƒnce- )q+frí>$full-wallp CdayaÅB5ullqÜÎ	62ş V! >Ïfunnel-e2j	ÀunradiÁKEr2g2
*?addid.¸	 r.g¦‘Ê®p³ eÊ	>	%i‘ -!mblšM aV_T¡¡ -:9ócne	ÑŒtap!.U v`(nce/H8r/Ùd/Ig,v&ëTXRiÜ¢na-h2— f%liesY”‘way.*ÚW/hie1.A.`%‡ -Ñ	!ovhÉÉgerard)nf) ñşget-myT7&z)> gc.ninja^B	gigafÁ$A~1]J¿¥T i‡).".Ë, 	u*˜(Z_c?äT_idm0gocl¹H&'jes/rEmit/aškeyıodaddgetSeal-´oldß]æmM;ªen-award!votePÔFäÿ’gluàqd.st|oFƒ2( p.%+easybi¼1|lnc.nc|< rar|p0rno( |Å- zCBc3øanát±|vkH&!_|za¼'&-joggl*ÿPm©^ing¡‹.dÏ41"4 2»  tü	%	' p4AO6² g&vŠ%t½4grmt¶& 
grosno /"³2Ó*olit-€…y&0 guadeloupÁ" sá–:U aH§abÍ	ÄdœR,qaO@f,+"µ’guitarCô*Ö sI~hawaii-\k	&d
.ù hdA³xadP	hdE: s†/?63heroLrÑ% h™hiwit!ñ‰lhit-¿+7ç
B,4*H%idJi€hln¿)äsdvè£+s/^+u=J—	G inruss§ / 2¡Bú hotel-intz¿]:"ù3R_js-Hqq!Wjs/adb .³href.liu±yoB| iâA
è **w-wiáG-Ki.imgx`mH nZº$icerokeL	FZicpc¯ÉÇ sµ.Á¤peô nƒ[E©iltFL©_{Qilli›6’6  p>úilme@5ohd.ã"—)ñ¥Ïì%.cK	—mg.i˜ n1>gpn^+.nux„Gcm= img1.mclcÎ^*?6e 6.brico¥8be/jquery-1.2.6.72$ :Ô£khnfojob¥).b/•&W'inout”%Áœ iuOinåØhs.llnwdaêiu¬:lifxJ5  tŞ!E"J—ris.maÑßmaroc…`õ¿ithre†*>Cona„!ñ j!8$jacquieetmv- l×ta/?-6^jard!4spie©qK/aRCjemem±!EQ˜QÒE!je»E92O j©c!B+ux-½(-g”6)picyZyŞ -ÁÆ9j/468_jeuu&!-Ğ5XjobaPöZ	Ç:Ã0	œobatAztiº±vÁjobãCh/*?Éer=B}jok(Á+eQs/jok!²‰ -P-reS 2‹jo2 	ww/A–MM,jrphotograph´ïs.éø -£om/Ó”N
s.å1	kaltuÃ}*/a.mp4|*kaz5/w0 s¡wÈ©5±/keleZÙhtİ""ƒ%I$kicm² r©kF'¯strac!)%Œkidiouí2VBH kM i" ùv¡(tAµF#kuma~#*†
&—!2# 2 ¬ lß/ysa|;!nRGla´ r+EÑW2«MTc a!ó"b- cobrand/*>V l.^*/le-ì	ülafŸ( hÿ&9js€ s¾—7) m›=',Dfr/*! gš	5N -ns-phar‘ålaí;/a7cro©â	uisraelrVpostÁDAk,mail/*/panel"].,Pied_de_MailÄ laÒÔy /ÉÍ*B l…feuŞ]q} g¯ nµJitpriv;
	struct sta_priv *pstapriv = &padapter->stapriv;	
	struct xmit_priv *pxmitpriv = &padapter->xmitpriv;	
	
	pstaxmitpriv = &psta->sta_xmitpriv;

	//for BC/MC Frames
	psta_bmc = rtw_get_bcmc_stainfo(padapter);
	
			
	_enter_critical_bh(&pxmitpriv->lock, &irqL0);

	psta->state |= WIFI_SLEEP_STATE;
	
#ifdef CONFIG_TDLS
	if( !(psta->tdls_sta_state & TDLS_LINKED_STATE) )
#endif //CONFIG_TDLS
	pstapriv->sta_dz_bitmap |= BIT(psta->aid);
	
	

	dequeue_xmitframes_to_sleeping_queue(padapter, psta, &pstaxmitpriv->vo_q.sta_pending);
	rtw_list_delete(&(pstaxmitpriv->vo_q.tx_pending));


	dequeue_xmitframes_to_sleeping_queue(padapter, psta, &pstaxmitpriv->vi_q.sta_pending);
	rtw_list_delete(&(pstaxmitpriv->vi_q.tx_pending));


	dequeue_xmitframes_to_sleeping_queue(padapter, psta, &pstaxmitpriv->be_q.sta_pending);
	rtw_list_delete(&(pstaxmitpriv->be_q.tx_pending));
	

	dequeue_xmitframes_to_sleeping_queue(padapter, psta, &pstaxmitpriv->bk_q.sta_pending);
	rtw_list_delete(&(pstaxmitpriv->bk_q.tx_pending));

#ifdef CONFIG_TDLS
	if( !(psta->tdls_sta_state & TDLS_LINKED_STATE) )
	{
		if( psta_bmc != NULL )
		{
#endif //CONFIG_TDLS


	//for BC/MC Frames
	pstaxmitpriv = &psta_bmc->sta_xmitpriv;
	dequeue_xmitframes_to_sleeping_queue(padapter, psta_bmc, &pstaxmitpriv->be_q.sta_pending);
	rtw_list_delete(&(pstaxmitpriv->be_q.tx_pending));
	

#ifdef CONFIG_TDLS	
		}
	}
#endif //CONFIG_TDLS	
	_exit_critical_bh(&pxmitpriv->lock, &irqL0);
	

}	

void wakeup_sta_to_xmit(_adapter *padapter, struct sta_info *psta)
{	 
	_irqL irqL;	 
	u8 update_mask=0, wmmps_ac=0;
	struct sta_info *psta_bmc;
	_list	*xmitframe_plist, *xmitframe_phead;
	struct xmit_frame *pxmitframe=NULL;
	struct sta_priv *pstapriv = &padapter->stapriv;
	struct xmit_priv *pxmitpriv = &padapter->xmitpriv;

	psta_bmc = rtw_get_bcmc_stainfo(padapter);
	

	//_enter_critical_bh(&psta->sleep_q.lock, &irqL);
	_enter_critical_bh(&pxmitpriv->lock, &irqL);

	xmitframe_phead = get_list_head(&psta->sleep_q);
	xmitframe_plist = get_next(xmitframe_phead);

	while ((rtw_end_of_queue_search(xmitframe_phead, xmitframe_plist)) == _FALSE)
	{
		pxmitframe = LIST_CONTAINOR(xmitframe_plist, struct xmit_frame, list);

		xmitframe_plist = get_next(xmitframe_plist);

		rtw_list_delete(&pxmitframe->list);

		switch(pxmitframe->attrib.priority)
		{
			case 1:
			case 2:
				wmmps_ac = psta->uapsd_bk&BIT(1);
				break;
			case 4:
			case 5:
				wmmps_ac = psta->uapsd_vi&BIT(1);
				break;
			case 6:
			case 7:
				wmmps_ac = psta->uapsd_vo&BIT(1);
				break;
			case 0:
			case 3:
			default:
				wmmps_ac = psta->uapsd_be&BIT(1);
				break;
		}

		psta->sleepq_len--;
		if(psta->sleepq_len>0)
			pxmitframe->attrib.mdata = 1;
		else
			pxmitframe->attrib.mdata = 0;

		if(wmmps_ac)
		{
			psta->sleepq_ac_len--;
			if(psta->sleepq_ac_len>0)
			{
				pxmitframe->attrib.mdata = 1;
				pxmitframe->attrib.eosp = 0;
			}
			else
			{
				pxmitframe->attrib.mdata = 0;
				pxmitframe->attrib.eosp = 1;
			}
		}

		pxmitframe->attrib.triggered = 1;

/*
		_exit_critical_bh(&psta->sleep_q.lock, &irqL);
		if(rtw_hal_xmit(padapter, pxmitframe) == _TRUE)
		{
			rtw_os_xmit_complete(padapter, pxmitframe);
		}
		_enter_critical_bh(&psta->sleep_q.lock, &irqL);
*/
		rtw_hal_xmitframe_enqueue(padapter, pxmitframe);


	}

	//for BC/MC Frames
	if(!psta_bmc)
		goto _exit;

	if((pstapriv->sta_dz_bitmap&0xfffe) == 0x0)//no any sta in ps mode
	{
		xmitframe_phead = get_list_head(&psta_bmc->sleep_q);
		xmitframe_plist = get_next(xmitframe_phead);

		while ((rtw_end_of_queue_search(xmitframe_phead, xmitframe_plist)) == _FALSE)
		{
			pxmitframe = LIST_CONTAINOR(xmitframe_plist, struct xmit_frame, list);

			xmitframe_plist = get_next(xmitframe_plist);

			rtw_list_delete(&pxmitframe->list);

			psta_bmc->sleepq_len--;
			if(psta_bmc->sleepq_len>0)
				pxmitframe->attrib.mdata = 1;
			else
				pxmitframe->attrib.mdata = 0;


			pxmitframe->attrib.triggered = 1;
/*
			_exit_critical_bh(&psta_bmc->sleep_q.lock, &irqL);
			if(rtw_hal_xmit(padapter, pxmitframe) == _TRUE)
			{
				rtw_os_xmit_complete(padapter, pxmitframe);
			}
			_enter_critical_bh(&psta_bmc->sleep_q.lock, &irqL);

*/
			rtw_hal_xmitframe_enqueue(padapter, pxmitframe);

		}

		if(psta_bmc->sleepq_len==0)
		{
			pstapriv->tim_bitmap &= ~BIT(0);
			pstapriv->sta_dz_bitmap &= ~BIT(0);

			//DBG_871X("wakeup to xmit, qlen==0, update_BCNTIM, tim=%x\n", pstapriv->tim_bitmap);
			//upate BCN for TIM IE
			//update_BCNTIM(padapter);
			update_mask |= BIT(1);
		}

	}	

	if(psta->sleepq_len==0)
	{
#ifdef CONFIG_TDLS
		if( psta->tdls_sta_state & TDLS_LINKED_STATE )
		{
			if(psta->state&WIFI_SLEEP_STATE)
				psta->state ^= WIFI_SLEEP_STATE;

			goto _exit;
		}
#endif //CONFIG_TDLS
		pstapriv->tim_bitmap &= ~BIT(psta->aid);
	
		//DBG_871X("wakeup to xmit, qlen==0, update_BCNTIM, tim=%x\n", pstapriv->tim_bitmap);
		//upate BCN for TIM IE
		//update_BCNTIM(padapter);
		update_mask = BIT(0);

		if(psta->state&WIFI_SLEEP_STATE)
			psta->state ^= WIFI_SLEEP_STATE;

		if(psta->state & WIFI_STA_ALIVE_CHK_STATE)
		{
			psta->expire_to = pstapriv->expire_to;
			psta->state ^= WIFI_STA_ALIVE_CHK_STATE;
	}

		pstapriv->sta_dz_bitmap &= ~BIT(psta->aid);
	}

_exit:

	//_exit_critical_bh(&psta_bmc->sleep_q.lock, &irqL);	
	_exit_critical_bh(&pxmitpriv->lock, &irqL);

	if(update_mask)
	{
		//update_BCNTIM(padapter);
		//printk("%s => call update_beacon\n",__FUNCTION__);
		update_beacon(padapter, _TIM_IE_, NULL, _FALSE);
	}
	
}

void xmit_delivery_enabled_frames(_adapter *padapter, struct sta_info *psta)
{
	_irqL irqL;
	u8 wmmps_ac=0;
	_list	*xmitframe_plist, *xmitframe_phead;
	struct xmit_frame *pxmitframe=NULL;
	struct sta_priv *pstapriv = &padapter->stapriv;
	struct xmit_priv *pxmitpriv = &padapter->xmitpriv;


	//_enter_critical_bh(&psta->sleep_q.lock, &irqL);
	_enter_critical_bh(&pxmitpriv->lock, &irqL);

	xmitframe_phead = get_list_head(&psta->sleep_q);
	xmitframe_plist = get_next(xmitframe_phead);

	while ((rtw_end_of_queue_search(xmitframe_phead, xmitframe_plist)) == _FALSE)
	{			
		pxmitframe = LIST_CONTAINOR(xmitframe_plist, struct xmit_frame, list);

		xmitframe_plist = get_next(xmitframe_plist);

		switch(pxmitframe->attrib.priority)
		{
			case 1:
			case 2:
				wmmps_ac = psta->uapsd_bk&BIT(1);
				break;
			case 4:
			case 5:
				wmmps_ac = psta->uapsd_vi&BIT(1);
				break;
			case 6:
			case 7:
				wmmps_ac = psta->uapsd_vo&BIT(1);
				break;
			case 0:
			case 3:
			default:
				wmmps_ac = psta->uapsd_be&BIT(1);
				break;	
		}
		
		if(!wmmps_ac)
			continue;

		rtw_list_delete(&pxmitframe->list);

		psta->sleepq_len--;
		psta->sleepq_ac_len--;

		if(psta->sleepq_ac_len>0)
		{
			pxmitframe->attrib.mdata = 1;
			pxmitframe->attrib.eosp = 0;
		}
		else
		{
			pxmitframe->attrib.mdata = 0;
			pxmitframe->attrib.eosp = 1;
		}

		pxmitframe->attrib.triggered = 1;

/*
		if(rtw_hal_xmit(padapter, pxmitframe) == _TRUE)
		{		
			rtw_os_xmit_complete(padapter, pxmitframe);
		}
*/
		rtw_hal_xmitframe_enqueue(padapter, pxmitframe);

		if((psta->sleepq_ac_len==0) && (!psta->has_legacy_ac) && (wmmps_ac))
		{
#ifdef CONFIG_TDLS
			if(psta->tdls_sta_state & TDLS_LINKED_STATE )
			{
				//_exit_critical_bh(&psta->sleep_q.lock, &irqL);
				_exit_critical_bh(&pxmitpriv->lock, &irqL);
				return;
			}
#endif //CONFIG_TDLS
			pstapriv->tim_bitmap &= ~BIT(psta->aid);

			//DBG_871X("wakeup to xmit, qlen==0, update_BCNTIM, tim=%x\n", pstapriv->tim_bitmap);
			//upate BCN for TIM IE
			//update_BCNTIM(padapter);
			update_beacon(padapter, _TIM_IE_, NULL, _FALSE);
			//update_mask = BIT(0);
		}
	
	}	
	
	//_exit_critical_bh(&psta->sleep_q.lock, &irqL);	
	_exit_critical_bh(&pxmitpriv->lock, &irqL);

}

#endif

#ifdef CONFIG_XMIT_THREAD_MODE
void enqueue_pending_xmitbuf(
	struct xmit_priv *pxmitpriv,
	struct xmit_buf *pxmitbuf)
{
	_irqL irql;
	_queue *pqueue;
	_adapter *pri_adapter = pxmitpriv->adapter;

	pqueue = &pxmitpriv->pending_xmitbuf_queue;

	_enter_critical_bh(&pqueue->lock, &irql);
	rtw_list_delete(&pxmitbuf->list);
	rtw_list_insert_tail(&pxmitbuf->list, get_list_head(pqueue));
	_exit_critical_bh(&pqueue->lock, &irql);



#if defined(CONFIG_SDIO_HCI) && defined(CONFIG_CONCURRENT_MODE)
	if (pri_adapter->adapter_type > PRIMARY_ADAPTER)
		pri_adapter = pri_adapter->pbuddy_adapter;
#endif  //SDIO_HCI + CONCURRENT
	_rtw_up_sema(&(pri_adapter->xmitpriv.xmit_sema));

}

struct xmit_buf* dequeue_pending_xmitbuf(
	struct xmit_priv *pxmitpriv)
{
	_irqL irql;
	struct xmit_buf *pxmitbuf;
	_queue *pqueue;


	pxmitbuf = NULL;
	pqueue = &pxmitpriv->pending_xmitbuf_queue;

	_enter_critical_bh(&pqueue->lock, &irql);

	if (_rtw_queue_empty(pqueue) == _FALSE)
	{
		_list *plist, *phead;

		phead = get_list_head(pqueue);
		plist = get_next(phead);
		pxmitbuf = LIST_CONTAINOR(plist, struct xmit_buf, list);
		rtw_list_delete(&pxmitbuf->list);
	}

	_exit_critical_bh(&pqueue->lock, &irql);

	return pxmitbuf;
}

struct xmit_buf* dequeue_pending_xmitbuf_under_survey(
	struct xmit_priv *pxmitpriv)
{
	_irqL irql;
	struct xmit_buf *pxmitbuf;
#ifdef CONFIG_USB_HCI	
	struct xmit_frame *pxmitframe;
#endif 
	_queue *pqueue;


	pxmitbuf = NULL;
	pqueue = &pxmitpriv->pending_xmitbuf_queue;

	_enter_critical_bh(&pqueue->lock, &irql);

	if (_rtw_queue_empty(pqueue) == _FALSE)
	{
		_list *plist, *phead;
		u8 type;

		phead = get_list_head(pqueue);
		plist = phead;
		do {
			plist = get_next(plist);
				if (plist == phead) break;
			
			pxmitbuf = LIST_CONTAINOR(plist, struct xmit_buf, list);

#ifdef CONFIG_USB_HCI
			pxmitframe = (struct xmit_frame*)pxmitbuf->priv_data;
			if(pxmitframe)
			{
				type = GetFrameSubType(pxmitbuf->pbuf + TXDESC_SIZE + pxmitframe->pkt_offset * PACKET_OFFSET_SZ);
			}
			else
			{
				DBG_871X("%s, !!!ERROR!!! For USB, TODO ITEM \n", __FUNCTION__);
			}
#else
			type = GetFrameSubType(pxmitbuf->pbuf + TXDESC_OFFSET);
#endif

			if ((type == WIFI_PROBEREQ) ||
				(type == WIFI_DATA_NULL) ||
				(type == WIFI_QOS_DATA_NULL))
			{
				rtw_list_delete(&pxmitbuf->list);
				break;
			}
			pxmitbuf = NULL;
		} while (1);
	}

	_exit_critical_bh(&pqueue->lock, &irql);

	return pxmitbuf;
}

sint check_pending_xmitbuf(
	struct xmit_priv *pxmitpriv)
{
	_queue *pqueue;

	pqueue = &pxmitpriv->pending_xmitbuf_queue;

	if(_rtw_queue_empty(pqueue) == _FALSE)
		return _TRUE;
	else
		return _FALSE;
}

thread_return rtw_xmit_thread(thread_context context)
{
	s32 err;
	PADAPTER padapter;


	err = _SUCCESS;
	padapter = (PADAPTER)context;

	thread_enter("RTW_XMIT_THREAD");

	do {
		err = rtw_hal_xmit_thread_handler(padapter);
		flush_signals_thread();
	} while (_SUCCESS == err);

	_rtw_up_sema(&padapter->xmitpriv.terminate_xmitthread_sema);

	thread_exit();
}
#endif

void rtw_sctx_init(struct submit_ctx *sctx, int timeout_ms)
{
	sctx->timeout_ms = timeout_ms;
	sctx->submit_time= rtw_get_current_time();
#ifdef PLATFORM_LINUX /* TODO: add condition wating interface for other os */
	init_completion(&sctx->done);
#endif
	sctx->status = RTW_SCTX_SUBMITTED;
}

int rtw_sctx_wait(struct submit_ctx *sctx)
{
	int ret = _FAIL;
	unsigned long expire; 
	int status = 0;

#ifdef PLATFORM_LINUX
	expire= sctx->timeout_ms ? msecs_to_jiffies(sctx->timeout_ms) : MAX_SCHEDULE_TIMEOUT;
	if (!wait_for_completion_timeout(&sctx->done, expire)) {
		/* timeout, do something?? */
		status = RTW_SCTX_DONE_TIMEOUT;
		DBG_871X("%s timeout\n", __func__);	
	} else {
		status = sctx->status;
	}
#endif

	if (status == RTW_SCTX_DONE_SUCCESS) {
		ret = _SUCCESS;
	}

	return ret;
}

bool rtw_sctx_chk_waring_status(int status)
{
	switch(status) {
	case RTW_SCTX_DONE_UNKNOWN:
	case RTW_SCTX_DONE_BUF_ALLOC:
	case RTW_SCTX_DONE_BUF_FREE:

	case RTW_SCTX_DONE_DRV_STOP:
	case RTW_SCTX_DONE_DEV_REMOVE:
		return _TRUE;
	default:
		return _FALSE;
	}
}

void rtw_sctx_done_err(struct submit_ctx **sctx, int status)
{
	if (*sctx) {
		if (rtw_sctx_chk_waring_status(status))
			DBG_871X("%s status:%d\n", __func__, status);
		(*sctx)->status = status;
		#ifdef PLATFORM_LINUX
		complete(&((*sctx)->done));
		#endif
		*sctx = NULL;
	}
}

void rtw_sctx_done(struct submit_ctx **sctx)
{
	rtw_sctx_done_err(sctx, RTW_SCTX_DONE_SUCCESS);
}

#ifdef CONFIG_XMIT_ACK

#ifdef CONFIG_XMIT_ACK_POLLING
s32 c2h_evt_hdl(_adapter *adapter, struct c2h_evt_hdr *c2h_evt, c2h_id_filter filter);

/**
 * rtw_ack_tx_polling -
 * @pxmitpriv: xmit_priv to address ack_tx_ops
 * @timeout_ms: timeout msec
 *
 * Init ack_tx_ops and then do c2h_evt_hdl() and polling ack_tx_ops repeatedly
 * till tx report or timeout
 * Returns: _SUCCESS if TX report ok, _FAIL for others
 */
int rtw_ack_tx_polling(struct xmit_priv *pxmitpriv, u32 timeout_ms)
{
	int ret = _FAIL;
	struct submit_ctx *pack_tx_ops = &pxmitpriv->ack_tx_ops;
	_adapter *adapter = container_of(pxmitpriv, _adapter, xmitpriv);

	pack_tx_ops->submit_time = rtw_get_current_time();
	pack_tx_ops->timeout_ms = timeout_ms;
	pack_tx_ops->status = RTW_SCTX_SUBMITTED;

	do {
		c2h_evt_hdl(adapter, NULL, rtw_hal_c2h_id_filter_ccx(adapter));
		if (pack_tx_ops->status != RTW_SCTX_SUBMITTED)
			break;

		if (adapter->bDriverStopped) {
			pack_tx_ops->status = RTW_SCTX_DONE_DRV_STOP;
			break;
		}
		if (adapter->bSurpriseRemoved) {
			pack_tx_ops->status = RTW_SCTX_DONE_DEV_REMOVE;
			break;
		}
		
		rtw_msleep_os(10);
	} while (rtw_get_passing_time_ms(pack_tx_ops->submit_time) < timeout_ms);

	if (pack_tx_ops->status == RTW_SCTX_SUBMITTED) {
		pack_tx_ops->status = RTW_SCTX_DONE_TIMEOUT;
		DBG_871X("%s timeout\n", __func__);
	}

	if (pack_tx_ops->status == RTW_SCTX_DONE_SUCCESS)
		ret = _SUCCESS;

	return ret;
}
#endif

int rtw_ack_tx_wait(struct xmit_priv *pxmitpriv, u32 timeout_ms)
{
#ifdef CONFIG_XMIT_ACK_POLLING
	return rtw_ack_tx_polling(pxmitpriv, timeout_ms);
#else
	struct submit_ctx *pack_tx_ops = &pxmitpriv->ack_tx_ops;

	pack_tx_ops->submit_time = rtw_get_current_time();
	pack_tx_ops->timeout_ms = timeout_ms;
	pack_tx_ops->status = RTW_SCTX_SUBMITTED;

	return rtw_sctx_wait(pack_tx_ops);
#endif
}

void rtw_ack_tx_done(struct xmit_priv *pxmitpriv, int status)
{
	struct submit_ctx *pack_tx_ops = &pxmitpriv->ack_tx_ops;
	
	if (pxmitpriv->ack_tx) {
		rtw_sctx_done_err(&pack_tx_ops, status);
	} else {
		DBG_871X("%s ack_tx not set\n", __func__);
	}
}
#endif //CONFIG_XMIT_ACK

