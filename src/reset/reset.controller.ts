import { BadRequestException, Body, Controller ,NotFoundException,Post} from '@nestjs/common';
//import {MailserService} from 
import { ResetService } from './reset.service';

@Controller()
export class ResetController {
    constructor(private resetService:ResetService,
        /*private mailService:MailserService
          private authService:AuthService 
        */){
       
    }
    @Post('forgot')
    async forgot(@Body('email')email:string){
        const token=Math.random().toString(20).substr(2,12)
        await this.resetService.create({email,token})

        return {message:'check your mail to reset your password'}

       /* const url=`https://localhost:4200/reset/${token}`   
        await this.mailerService.sendMil({
            to:email,
            subject:'reset your password',
            html:`click<a href="${url}">hear</a>reset your password`
        })
        
         return {message:'check your mail'}*/
    }
    /*@Post('reset')
    async reset(
        @Body('token')token:string,
        @Body('password')password:string,
        @Body('password_confirm')password_confirm:string,
    ){
        if(password!==password_confirm)
        {
            throw new BadRequestException('password do not match')
        }
        const reset=await this.resetService.findOne({token})
        const email=reset.email
        const user=await this.authService.findOneBy({email})
        if(!user)
        {
            throw new NotFoundException("not found")
        }
        const hashedpassword=await bcrypt.hash(password,12)
        await this.authService.update(user.id,{password:hashedpassword})
        return {message:'success'}
    }*/
}
