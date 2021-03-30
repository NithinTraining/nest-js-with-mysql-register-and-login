import { BadRequestException, Body, Controller, Get, Post,Res,Req, UseInterceptors, ClassSerializerInterceptor } from '@nestjs/common';
import { AuthService } from './auth.service';
import * as bcrypt from 'bcrypt';
import {RegisterDto} from '../auth/dto/register.dto'
import { JwtService } from '@nestjs/jwt';
import {Request, Response} from 'express'
import { AuthInterceptor } from './auth.interceptor';
UseInterceptors(ClassSerializerInterceptor)
@Controller()

export class AuthController {
    constructor(private authService:AuthService,
                private jwtService:JwtService){

    }

    @Post('register')
    async register(@Body() body:RegisterDto){
        if(body.password!==body.password_conform)
        {
            throw new BadRequestException('password does not match')
        }
        const saltOrRounds=12
        body.password=await bcrypt.hash(body.password, saltOrRounds);
        return this.authService.create(body); 
    }

    @Post('login')
    async login(
        @Body('email')email:string,
        @Body('password')password:string,
        @Res({passthrough:true})response:Response
        ){
            const user=await this.authService.findOneBy({email})
            if(!user)
            {
                throw new BadRequestException('emil des not exist')  
            }
            if(!await bcrypt.compare(password,user.password))
            {
                throw new BadRequestException('invalid credential')  
            }
            const jwt=await this.jwtService.signAsync({user:user.id})
            response.cookie('jwt',jwt,{httpOnly:true})
            return user;
        }
        @UseInterceptors(AuthInterceptor)
        @Get('user')
        async user(@Req()request:Request){
            const cooki=request.cookies['jwt'];
            const data=await this.jwtService.verifyAsync(cooki)
            console.log(data)
            
            return this.authService.findOneBy({id:data['user']})
        }
        @UseInterceptors(AuthInterceptor)
        @Post('logout')
        async logot( @Res({passthrough:true})response:Response){
            response.clearCookie('jwt')
            return {
                message:'logut success'
            }

        }
}
