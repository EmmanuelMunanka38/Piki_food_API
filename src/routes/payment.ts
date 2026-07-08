import { Router,Response, Request } from "express";
import axios from "node_modules/axios/index.cjs";
import prisma from "@/db/prisma";

const router =Router();

router.post('/api/v1/payments/checkout ',async(req:Request,res:Response):Promise<void>=> {
    try {
        const baseUrl = process.env.CLICKPESA_BASE_URL 
        const {name,amount,phone,email} =  req.body;
        const merchanReference = `ORD-${Date.now()}`;

        const response = await axios.post(`${baseUrl}`,

            {
                amount: parseFloat(amount),
                currency: 'TZS',
                customerReference: merchanReference,
                customer:{
                    name:name,
                    phoneNumber:phone,
                    email:email,
                },

                paymentMethod:'Mobile_money' // need to check here * from clickpesa Documentaion !
            },
            {
                headers:{
                    'Authorization':'Bearer token ${this is also from  click_pesa __api key }',
                    'Content-Type':'application/json'
                }
            }
        );

        const clickPesaData = response.data;
        
        const transaction = await prisma.transaction.create(
            {
                data:{
                    oderReference:clickPesaData.oderReference || clickPesaData.id,
                    amount: parseFloat(amount),
                    phoneNumber: phone,
                    status: 'PENDING'
                }
            }
        )



    } catch (error) {
        console.error({message:error})
        res.status(404).json('NOT FOUND 404')
    }
})



router.post('/api/v1/clickpesa/webhook', async(req:Request,res:Response):Promise<void>=>{
    const {event,status}=req.body;
    try {
        if (event == 'PAYMENT RECIVED' && status == 'SUCCESS'){
            await prisma.transaction.update({
                where:{oderReference:data.oderReference},
                data:{status:'SUCCESS'}
            })
        }else await prisma.transaction.update({
            where:{oderReference:data.oderReference},
            data:{status:'FAILED'}
        })

        res.status(200).json('Webhook has processed ')

    } catch (error) {
        console.error({message:error})
        res.status(404).json('NOT FOUND 404')
    }
});